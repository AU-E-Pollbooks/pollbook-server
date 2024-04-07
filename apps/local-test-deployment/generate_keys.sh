#!/bin/bash
# This script generates key pairs for the two servers and four clients in local-test-deployment using OpenSSL commands

#openssl genpkey -algorithm rsa -outform PEM -out server0/private_key.pem
#openssl pkey -in server0/private_key.pem -out server0/checkin_pubkey.pem -pubout -outform PEM

#openssl genpkey -algorithm rsa -outform PEM -out server1/private_key.pem
#openssl pkey -in server1/private_key.pem -out server1/id_pubkey.pem -pubout -outform PEM

#cp server0/checkin_pubkey.pem server1
#cp server1/id_pubkey.pem server0
#mkdir -p server0/client_public_keys

#for num in {0..3}; do
#    cp server0/checkin_pubkey.pem client${num}
#    cp server1/id_pubkey.pem client${num}
#    openssl genpkey -algorithm rsa -outform PEM -out client${num}/private_key.pem
#    openssl pkey -in client${num}/private_key.pem -outform PEM -pubout -out server0/client_public_keys/client_pubkey_${num}.pem
#done

#cp -r server0/client_public_keys server1/

#generates x509 certificate/private key for local certificate authority for use in generating other certs
openssl req -new -newkey rsa -nodes -out ca.csr -keyout ca_key.pem -subj "/C=US/ST=Georgia/L=Augusta/O=AU/OU=SCCS/CN=Check In Server"
openssl x509 -trustout -signkey ca_key.pem -days 365 -req -in ca.csr -out ca_cert.pem

#generates x509 certificates/private keys for the two servers and four clients in local-test-deployment using OpenSSL commands
openssl req -x509 -newkey rsa -keyout server0/private_key.pem -out server0/checkin_certificate.csr -sha256 -days 365 -nodes -subj \
        "/C=US/ST=Georgia/L=Augusta/O=AU/OU=SCCS/CN=Check In Server"
openssl x509 -req -in server0/checkin_certificate.csr -CA ca_cert.pem -CAkey ca_key.pem -out server0/checkin_certificate.pem

openssl req -x509 -newkey rsa -keyout server1/private_key.pem -out server1/id_certificate.csr -sha256 -days 365 -nodes -subj \
        "/C=US/ST=Georgia/L=Augusta/O=AU/OU=SCCS/CN=Voter ID Server"
openssl x509 -req -in server1/id_certificate.csr -CA ca_cert.pem -CAkey ca_key.pem -out server1/id_certificate.pem

cp server0/checkin_certificate.pem server1
cp server1/id_certificate.pem server0

for num in {0..3}; do
    openssl req -x509 -newkey rsa -keyout client${num}/private_key.pem -out client${num}/certificate.csr \
    -sha256 -days 365 -nodes -subj "/C=US/ST=Georgia/L=Augusta/O=AU/OU=SCCS/CN=Client ${num}"
    openssl x509 -req -in client${num}/certificate.csr -CA ca_cert.pem -CAkey ca_key.pem -out client${num}/certificate.pem
done