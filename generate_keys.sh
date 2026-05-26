#!/bin/bash
set -euo pipefail

# --- Prepare directories ---
mkdir -p server0/ca server1/ca client0 client1 client2 client3
mkdir -p server0/client_public_keys server1/client_public_keys

# --- Create CA (with proper CA extensions) ---
# Key
openssl genrsa -out server0/ca/ca_key.pem 4096

# Self-signed CA cert (uses v3_ca from ca.cnf)
openssl req -x509 -new -sha256 -days 1825 \
  -key server0/ca/ca_key.pem \
  -out server0/ca/ca_cert.pem \
  -config ca.cnf

# Copy CA to others
cp -r server0/ca server1/
cp -r server0/ca client0/
cp -r server0/ca client1/
cp -r server0/ca client2/
cp -r server0/ca client3/

# --- SERVER 0: Check-in Server with SAN ---
# Key
openssl genrsa -out server0/private_key.pem 2048
# CSR with SAN (req_ext) from checkin_san.cnf
openssl req -new -sha256 \
  -key server0/private_key.pem \
  -out server0/checkin_certificate.csr \
  -config checkin_san.cnf

# Sign incl. SAN by referencing the SAME ext section at signing time
openssl x509 -req -sha256 -days 825 \
  -in server0/checkin_certificate.csr \
  -CA server0/ca/ca_cert.pem -CAkey server0/ca/ca_key.pem -CAcreateserial \
  -out server0/checkin_certificate.pem \
  -extensions req_ext -extfile checkin_san.cnf

# Export server public key (if you need it elsewhere)
openssl pkey -in server0/private_key.pem -pubout -out server0/checkin_pubkey.pem

# CSR no longer needed
rm -f server0/checkin_certificate.csr

# --- SERVER 1: Voter-ID Server with SAN ---
openssl genrsa -out server1/private_key.pem 2048
openssl req -new -sha256 \
  -key server1/private_key.pem \
  -out server1/id_certificate.csr \
  -config id_san.cnf

openssl x509 -req -sha256 -days 825 \
  -in server1/id_certificate.csr \
  -CA server1/ca/ca_cert.pem -CAkey server1/ca/ca_key.pem -CAcreateserial \
  -out server1/id_certificate.pem \
  -extensions req_ext -extfile id_san.cnf

openssl pkey -in server1/private_key.pem -pubout -out server1/id_pubkey.pem
rm -f server1/id_certificate.csr

# --- Cross-copy server certs/pubs if your code expects them cross-mounted ---
cp server0/checkin_certificate.pem server1/
cp server1/id_certificate.pem     server0/
cp server0/checkin_pubkey.pem     server1/
cp server1/id_pubkey.pem          server0/

# --- CLIENT CERTS (clientAuth EKU recommended) ---
# Minimal client template on the fly (no SAN required for mutual TLS)
cat > client_ext.cnf <<'EOF'
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

for num in 0 1 2 3; do
  openssl genrsa -out client${num}/private_key.pem 2048
  # Give each client a unique CN
  sed "s/CN = Pollbook Client/CN = Client ${num}/" client_ext.cnf > client${num}/client_ext_${num}.cnf

  openssl req -new -sha256 \
    -key client${num}/private_key.pem \
    -out client${num}/certificate.csr \
    -config client${num}/client_ext_${num}.cnf

  openssl x509 -req -sha256 -days 825 \
    -in client${num}/certificate.csr \
    -CA client${num}/ca/ca_cert.pem -CAkey client${num}/ca/ca_key.pem -CAcreateserial \
    -out client${num}/certificate.pem \
    -extensions req_ext -extfile client${num}/client_ext_${num}.cnf

  # If you still need the servers' pubkeys in clients:
  cp server0/checkin_pubkey.pem client${num}/
  cp server1/id_pubkey.pem      client${num}/

  rm -f client${num}/certificate.csr client${num}/client_ext_${num}.cnf
done

rm -f client_ext.cnf
echo "Done. Remember to restart/rebuild containers so they pick up the new certs."
