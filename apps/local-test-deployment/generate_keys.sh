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
mkdir server0/ca
openssl req -new -newkey rsa -nodes -out ca.csr -keyout server0/ca/ca_key.pem -subj "/C=US/ST=Georgia/L=Augusta/O=AU/OU=SCCS/CN=Certificate Authority"
openssl x509 -trustout -signkey server0/ca/ca_key.pem -days 365 -req -in ca.csr -out server0/ca/ca_cert.pem
rm ca.csr

#copy over the ca and ca cert into all folders
cp -r server0/ca server1/
cp -r server0/ca client0/
cp -r server0/ca client1/
cp -r server0/ca client2/
cp -r server0/ca client3/

#generates x509 certificates/private keys for the two servers and four clients in local-test-deployment using OpenSSL commands

#generate the certificate request for server 0
openssl req -new -newkey rsa -keyout server0/private_key.pem -out server0/checkin_certificate.csr -sha256 -nodes -subj "/C=US/ST=Georgia/L=Augusta/O=AU/OU=SCCS/CN=Check In Server"
#sign the certificate for server 0 using the CA
openssl x509 -req -days 365 -in server0/checkin_certificate.csr -CA server0/ca/ca_cert.pem -CAkey server0/ca/ca_key.pem -out server0/checkin_certificate.pem
#CSR is no longer needed, discard
rm server0/checkin_certificate.csr

#generate the certificate request for server 1
openssl req -new -newkey rsa -keyout server1/private_key.pem -out server1/id_certificate.csr -sha256 -nodes -subj "/C=US/ST=Georgia/L=Augusta/O=AU/OU=SCCS/CN=Voter ID Server"
#sign the certificate for server 1 using the CA
openssl x509 -req -days 365 -in server1/id_certificate.csr -CA server1/ca/ca_cert.pem -CAkey server1/ca/ca_key.pem -out server1/id_certificate.pem
#CSR is no longer needed, discard
rm server1/id_certificate.csr

#copy over the server0 cert to server1 and vice versa
cp server0/checkin_certificate.pem server1
cp server1/id_certificate.pem server0

#generate and sign all client certs 
for num in {0..3}; do
    openssl req -new -newkey rsa -keyout client${num}/private_key.pem -out client${num}/certificate.csr -sha256 -nodes -subj "/C=US/ST=Georgia/L=Augusta/O=AU/OU=SCCS/CN=Client ${num}"
    openssl x509 -req -days 365 -in client${num}/certificate.csr -CA client${num}/ca/ca_cert.pem -CAkey client${num}/ca/ca_key.pem -out client${num}/certificate.pem
    rm client${num}/certificate.csr
done