# Four-device physical deployment

This Ansible deployment prepares one check-in server, one voter-ID server, and
one or more physical pollbook clients. The example inventory contains two
clients, for four devices total. It is separate from the Docker deployment.

The playbook installs role-specific configuration, PKI, and data under
`/opt/pollbook` by default. It never copies the CA private key, and each remote
host receives only its own private key.

## What to edit for a real site

1. In `inventory.yml`, set every `ansible_host` and the shared `ansible_user`.
   Keep each host in exactly one role group.
2. Set each client's unique, non-negative `client_id`.
3. Set the server `certificate_sans` to every DNS name and IP address clients
   may use to reach that server. SAN entries use `DNS:name` or `IP:address`.
4. In `group_vars/pollbook_devices.yml`, set the two advertised service
   addresses, ports, remote owner/group, installation path, and trusted client
   IDs. The advertised addresses should appear in the corresponding server
   certificate SAN list.
5. Confirm the controller versions of `data/voters.csv` and
   `data/id_voters.csv` are the datasets intended for deployment.

The remote account and owner/group must already exist. If it cannot write the
installation directory directly, leave `ansible_become: true` and ensure it has
working sudo access.

## Generate the deployment PKI

Run from this directory:

```bash
chmod +x generate_device_pki.sh
./generate_device_pki.sh --check-inventory
./generate_device_pki.sh
```

The check-only command validates and displays the inventory-derived identities
without creating keys. The generator reads `inventory.yml`, creates one CA, issues server certificates
with the configured SANs, and issues client certificates whose common names are
exactly `Client N`. That common-name format is currently parsed by both server
implementations.

The generated tree is:

```text
secrets/
  ca/
    ca_cert.pem
    ca_key.pem
  devices/
    checkin/{private_key.pem,certificate.pem}
    voter-id/{private_key.pem,certificate.pem}
    client-0/{private_key.pem,certificate.pem}
    client-1/{private_key.pem,certificate.pem}
  shared/
    ca_cert.pem
    checkin_certificate.pem
    checkin_pubkey.pem
    id_certificate.pem
    id_pubkey.pem
    client_pubkeys/<configured-prefix><client_id>.pem
```

If both identity files already exist, the generator validates and reuses them.
It refuses incomplete or mismatched identities instead of silently rotating
keys. It also refuses a reused server certificate if it lacks any SAN currently
configured in the inventory. To intentionally rotate an identity, first move
that host's directory to secure backup storage. Back up
`secrets/ca/ca_key.pem` separately; losing it
prevents new certificate issuance, while leaking it compromises the deployment.

To use an established CA, place its matching `ca_key.pem` and `ca_cert.pem` in
`secrets/ca/` before running the generator. Do not copy the CA private key to a
device.

## Validate and deploy

Confirm SSH host keys before the first deployment, then run:

```bash
ansible pollbook_devices -m ping
ansible-playbook deploy.yml --syntax-check
ansible-playbook deploy.yml --tags preflight
ansible-playbook deploy.yml --check --diff
ansible-playbook deploy.yml
```

The tagged preflight checks the complete local bundle without contacting the
devices. It also runs automatically before every full deployment and completes
before Ansible changes any device. It
refuses a deployment unless:

- there is exactly one host in each server group and at least one client;
- client IDs are present, numeric, non-negative, and unique;
- every trusted client ID exists in the client inventory;
- all required local paths are regular files;
- all certificates chain to the deployment CA for the proper TLS purpose;
- each certificate matches its private key;
- each client certificate contains the expected `Client N` identity; and
- exported server public keys match their certificates.

Ansible then deploys one host at a time and stops on the first failure. Repeated
runs are idempotent; replacement files receive Ansible backups.

## Files installed on devices

Every device receives:

- `config.ini` (`0640`)
- `pki/private_key.pem` (`0600`, unique to the device)
- `pki/certificate.pem` (unique to the device)
- the CA certificate and both server certificates/public keys

Both servers also receive `pki/client_pubkeys/`. The check-in server receives
`data/voters.csv` and `data/trusted_clients.txt`; the ID server receives its
version of `data/voters.csv` from the repository's `data/id_voters.csv`.

## Hardware-dependent work still required

This playbook deliberately does not install an application binary, create an OS
account, configure a firewall, or manage a service. Those details depend on the
eventual device OS, CPU architecture, build artifact, and service manager. Once
those are known, they can be added as variables and handlers without changing
the inventory role model or PKI layout established here.
