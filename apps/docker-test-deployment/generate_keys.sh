#!/bin/bash
# This script generates key pairs for the two servers and four clients in docker-test-deployment using OpenSSL commands

#generate x509 certificate/private key for local certificate authority for use in generating other certs
mkdir ca
openssl req -new -newkey rsa -nodes -out ca.csr -keyout ca/ca_key.pem -subj "/C=US/ST=Georgia/L=Augusta/O=AU/OU=SCCS/CN=Certificate Authority"
openssl x509 -trustout -signkey ca/ca_key.pem -days 365 -req -in ca.csr -out ca/ca_cert.pem
rm ca.csr

#copy the ca certificate into all folders
mkdir -p checkin_server/ca
cp ca/ca_cert.pem checkin_server/ca/
cp -r checkin_server/ca id_server/
for num in {0..3}; do
    cp -r checkin_server/ca client${num}/
done

#generate x509 certificates/private keys for the two servers and four clients

#generate the certificate request for server 0
openssl req -new -newkey rsa -keyout checkin_server/private_key.pem -out checkin_server/checkin_certificate.csr -sha256 -nodes -subj "/C=US/ST=Georgia/L=Augusta/O=AU/OU=SCCS/CN=Check In Server"
openssl pkey -in checkin_server/private_key.pem -out checkin_server/checkin_pubkey.pem -pubout -outform PEM
#sign the certificate for server 0 using the CA
openssl x509 -req -days 365 -in checkin_server/checkin_certificate.csr -CA ca/ca_cert.pem -CAkey ca/ca_key.pem -out checkin_server/checkin_certificate.pem
#CSR is no longer needed, discard
rm checkin_server/checkin_certificate.csr

#generate the certificate request for server 1
openssl req -new -newkey rsa -keyout id_server/private_key.pem -out id_server/id_certificate.csr -sha256 -nodes -subj "/C=US/ST=Georgia/L=Augusta/O=AU/OU=SCCS/CN=Voter ID Server"
openssl pkey -in id_server/private_key.pem -out id_server/id_pubkey.pem -pubout -outform PEM
#sign the certificate for server 1 using the CA
openssl x509 -req -days 365 -in id_server/id_certificate.csr -CA ca/ca_cert.pem -CAkey ca/ca_key.pem -out id_server/id_certificate.pem
#CSR is no longer needed, discard
rm id_server/id_certificate.csr

#copy over the checkin_server cert to id_server and vice versa
cp checkin_server/checkin_certificate.pem id_server
cp id_server/id_certificate.pem checkin_server
cp checkin_server/checkin_pubkey.pem id_server
cp id_server/id_pubkey.pem checkin_server

#generate and sign all client certs
for num in {0..3}; do
    cp checkin_server/checkin_pubkey.pem client${num}
    cp id_server/id_pubkey.pem client${num}
    openssl req -new -newkey rsa -keyout client${num}/private_key.pem -out client${num}/certificate.csr -sha256 -nodes -subj "/C=US/ST=Georgia/L=Augusta/O=AU/OU=SCCS/CN=Client ${num}"
    openssl x509 -req -days 365 -in client${num}/certificate.csr -CA ca/ca_cert.pem -CAkey ca/ca_key.pem -out client${num}/certificate.pem
    rm client${num}/certificate.csr
done
