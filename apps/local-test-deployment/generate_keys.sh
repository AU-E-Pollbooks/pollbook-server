#!/bin/bash
# This script generates key pairs for the two servers and four clients in local-test-deployment using OpenSSL commands

openssl genpkey -algorithm rsa -outform PEM -out server0/private_key.pem
openssl pkey -in server0/private_key.pem -out server0/checkin_pubkey.pem -pubout -outform PEM

openssl genpkey -algorithm rsa -outform PEM -out server1/private_key.pem
openssl pkey -in server1/private_key.pem -out server1/id_pubkey.pem -pubout -outform PEM

cp server0/checkin_pubkey.pem server1
cp server1/id_pubkey.pem server0
mkdir -p server0/client_public_keys

for num in {0..3}; do
    cp server0/checkin_pubkey.pem client${num}
    cp server1/id_pubkey.pem client${num}
    openssl genpkey -algorithm rsa -outform PEM -out client${num}/private_key.pem
    openssl pkey -in client${num}/private_key.pem -outform PEM -pubout -out server0/client_public_keys/client_pubkey_${num}.pem
done

cp -r server0/client_public_keys server1/


