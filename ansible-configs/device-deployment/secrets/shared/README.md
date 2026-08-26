`generate_device_pki.sh` populates this directory with the public deployment
bundle:

- `ca_cert.pem`
- `checkin_certificate.pem`
- `checkin_pubkey.pem`
- `id_certificate.pem`
- `id_pubkey.pem`
- `client_pubkeys/<configured-prefix><client_id>.pem`

No private key belongs in this shared directory. Device private keys remain in
`../devices/<inventory-host>/private_key.pem`, and the CA private key remains in
`../ca/ca_key.pem`. The generated contents of the parent `secrets/` directory
are gitignored.
