#!/bin/bash
# Generates key pairs for 2 servers and 4 clients with correct CA and SANs

set -e

# --- Create CA config ---
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

mkdir -p ca
openssl req -new -x509 -days 365 -keyout ca/ca_key.pem -out ca/ca_cert.pem -nodes -config ca.cnf -extensions v3_ca
rm ca.cnf

# --- Copy CA cert ---
mkdir -p checkin_server/ca
cp ca/ca_cert.pem checkin_server/ca/
cp -r checkin_server/ca id_server/
for num in {0..3}; do
    cp -r checkin_server/ca client${num}/
done

# --- Create config for Check-In Server ---
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

# --- Check-In Server cert + key ---
openssl req -new -newkey rsa -keyout checkin_server/private_key.pem -out checkin_server/checkin_certificate.csr -sha256 -nodes -config checkin.cnf
openssl x509 -req -days 365 -in checkin_server/checkin_certificate.csr \
    -CA ca/ca_cert.pem -CAkey ca/ca_key.pem -out checkin_server/checkin_certificate.pem \
    -extensions v3_req -extfile checkin.cnf
openssl pkey -in checkin_server/private_key.pem -out checkin_server/checkin_pubkey.pem -pubout -outform PEM
rm checkin_server/checkin_certificate.csr checkin.cnf

# --- Create config for ID Server ---
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

# --- ID Server cert + key ---
openssl req -new -newkey rsa -keyout id_server/private_key.pem -out id_server/id_certificate.csr -sha256 -nodes -config id.cnf
openssl x509 -req -days 365 -in id_server/id_certificate.csr \
    -CA ca/ca_cert.pem -CAkey ca/ca_key.pem -out id_server/id_certificate.pem \
    -extensions v3_req -extfile id.cnf
openssl pkey -in id_server/private_key.pem -out id_server/id_pubkey.pem -pubout -outform PEM
rm id_server/id_certificate.csr id.cnf

# --- Share server certs and pubkeys ---
cp checkin_server/checkin_certificate.pem id_server/
cp id_server/id_certificate.pem checkin_server/
cp checkin_server/checkin_pubkey.pem id_server/
cp id_server/id_pubkey.pem checkin_server/

# --- Clients: generate key/cert signed by CA ---
for num in {0..3}; do
    cp checkin_server/checkin_pubkey.pem client${num}/
    cp id_server/id_pubkey.pem client${num}/
    openssl req -new -newkey rsa -keyout client${num}/private_key.pem \
        -out client${num}/certificate.csr -sha256 -nodes -subj "/C=US/ST=Georgia/L=Augusta/O=AU/OU=SCCS/CN=Client ${num}"
    openssl x509 -req -days 365 -in client${num}/certificate.csr \
        -CA ca/ca_cert.pem -CAkey ca/ca_key.pem -out client${num}/certificate.pem
    rm client${num}/certificate.csr
done
