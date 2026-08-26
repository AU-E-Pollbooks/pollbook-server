#!/bin/bash
# Generates key pairs for 2 servers and N clients under ONE shared CA.
# Merge of the two prior generate_keys.sh variants:
#   - base/structure + race-test alt identity ....... from apps/docker-test-deployment
#   - strict mode, clientAuth EKU, 4096-bit CA,
#     longer validity, -CAcreateserial, pubkey dirs .. from root generate_keys.sh
#   - $1 = client count + seq-loop scaling .......... NEW (fixes the {0..3} bug)
#
# Usage:  ./generate_keys.sh [N]        (N = number of clients, default 4)
# Invoked by ansible full_deploy.yml as:  ./generate_keys.sh {{ total_n }}

set -euo pipefail                                   # [root] strict: unset vars + pipe failures

N="${1:-4}"                                         # [scaling] client count (clients 0..N-1)

mkdir -p ca checkin_server/ca id_server/ca \
         checkin_server/client_public_keys \
         id_server/client_public_keys              # [root] servers store learned client pubkeys here

# --- CA (4096-bit, long-lived) -----------------------------------------------
cat >ca.cnf <<EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]
C = US
ST = Georgia
L = Augusta
O = AU
OU = SCCS
CN = Certificate Authority

[ v3_ca ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

openssl genrsa -out ca/ca_key.pem 4096             # [root] 4096-bit CA key
openssl req -x509 -new -sha256 -days 1825 \
    -key ca/ca_key.pem -out ca/ca_cert.pem \
    -config ca.cnf -extensions v3_ca
rm ca.cnf

# --- Distribute the CA *cert only* (never the CA key) to every party ----------
cp ca/ca_cert.pem checkin_server/ca/
cp ca/ca_cert.pem id_server/ca/
for num in $(seq 0 $((N-1))); do                   # [scaling] all N clients, not {0..3}
    mkdir -p client${num}/ca
    cp ca/ca_cert.pem client${num}/ca/
done

# --- Check-In Server cert (SAN 172.16.0.5) -----------------------------------
cat >checkin.cnf <<EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
C = US
ST = Georgia
L = Augusta
O = AU
OU = SCCS
CN = Check In Server

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = 172.16.0.5
EOF

openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout checkin_server/private_key.pem \
    -out checkin_server/checkin_certificate.csr -config checkin.cnf
openssl x509 -req -sha256 -days 825 \
    -in checkin_server/checkin_certificate.csr \
    -CA ca/ca_cert.pem -CAkey ca/ca_key.pem -CAcreateserial \
    -out checkin_server/checkin_certificate.pem \
    -extensions v3_req -extfile checkin.cnf        # [root] -CAcreateserial
openssl pkey -in checkin_server/private_key.pem \
    -out checkin_server/checkin_pubkey.pem -pubout -outform PEM
rm checkin_server/checkin_certificate.csr checkin.cnf

# --- ID Server cert (SAN 172.16.0.6) -----------------------------------------
cat >id.cnf <<EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
C = US
ST = Georgia
L = Augusta
O = AU
OU = SCCS
CN = Voter ID Server

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = 172.16.0.6
EOF

openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout id_server/private_key.pem \
    -out id_server/id_certificate.csr -config id.cnf
openssl x509 -req -sha256 -days 825 \
    -in id_server/id_certificate.csr \
    -CA ca/ca_cert.pem -CAkey ca/ca_key.pem -CAcreateserial \
    -out id_server/id_certificate.pem \
    -extensions v3_req -extfile id.cnf
openssl pkey -in id_server/private_key.pem \
    -out id_server/id_pubkey.pem -pubout -outform PEM
rm id_server/id_certificate.csr id.cnf

# --- Share server certs and pubkeys (cross-mounted by the services) ----------
cp checkin_server/checkin_certificate.pem id_server/
cp id_server/id_certificate.pem checkin_server/
cp checkin_server/checkin_pubkey.pem id_server/
cp id_server/id_pubkey.pem checkin_server/

# --- Client cert template (clientAuth EKU) -----------------------------------
cat >client_ext.cnf <<'EOF'
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
C  = US
ST = Georgia
L  = Augusta
O  = AU
OU = SCCS
CN = Pollbook Client

[ req_ext ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# --- Clients: key + CA-signed cert (clientAuth), signed by the shared CA ------
for num in $(seq 0 $((N-1))); do                   # [scaling] all N clients
    mkdir -p client${num}
    cp checkin_server/checkin_pubkey.pem client${num}/
    cp id_server/id_pubkey.pem client${num}/

    sed "s/CN = Pollbook Client/CN = Client ${num}/" client_ext.cnf \
        >client${num}/client_ext_${num}.cnf        # [root] per-client unique CN

    openssl req -new -newkey rsa:2048 -nodes -sha256 \
        -keyout client${num}/private_key.pem \
        -out client${num}/certificate.csr \
        -config client${num}/client_ext_${num}.cnf
    openssl x509 -req -sha256 -days 825 \
        -in client${num}/certificate.csr \
        -CA ca/ca_cert.pem -CAkey ca/ca_key.pem -CAcreateserial \
        -out client${num}/certificate.pem \
        -extensions req_ext -extfile client${num}/client_ext_${num}.cnf  # [root] EKU
    rm client${num}/certificate.csr client${num}/client_ext_${num}.cnf
done
rm client_ext.cnf

# --- Race-test alt identity --------------------------------------------------
# [apps] client0 additionally carries Client 2's freshly-signed key+cert as an
# "alt" identity, so the race-condition test can drive two distinct untrusted
# clients (Client 0 + Client 2) from inside the single untrusted-client-0
# container. Requires at least 3 clients (0,1,2).
if [ "$N" -ge 3 ]; then
    cp client2/private_key.pem  client0/private_key_alt.pem
    cp client2/certificate.pem  client0/certificate_alt.pem
fi

echo "Done: 1 CA, 2 servers, ${N} clients (0..$((N-1))). Restart/rebuild containers to pick up new certs."
