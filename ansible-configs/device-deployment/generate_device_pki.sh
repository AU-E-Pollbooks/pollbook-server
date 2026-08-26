#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
inventory_file="${script_dir}/inventory.yml"
secrets_dir="${script_dir}/secrets"
ca_dir="${secrets_dir}/ca"
devices_dir="${secrets_dir}/devices"
shared_dir="${secrets_dir}/shared"
client_pubkeys_dir="${shared_dir}/client_pubkeys"

case "${1:-}" in
    "") inventory_check_only=false ;;
    --check-inventory) inventory_check_only=true ;;
    *)
        echo "Usage: $0 [--check-inventory]" >&2
        exit 2
        ;;
esac

for command_name in ansible-inventory python3 openssl; do
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        echo "Required command not found: ${command_name}" >&2
        exit 1
    fi
done

inventory_json="$(ansible-inventory -i "${inventory_file}" --list)"
mapfile -t inventory_records < <(
    python3 -c '
import ipaddress
import json
import re
import sys

inventory = json.load(sys.stdin)
hostvars = inventory.get("_meta", {}).get("hostvars", {})
role_groups = {
    "checkin": inventory.get("checkin_servers", {}).get("hosts", []),
    "id": inventory.get("id_servers", {}).get("hosts", []),
    "client": inventory.get("pollbook_clients", {}).get("hosts", []),
}

if len(role_groups["checkin"]) != 1 or len(role_groups["id"]) != 1:
    raise SystemExit("Inventory must define exactly one check-in and one ID server")
if not role_groups["client"]:
    raise SystemExit("Inventory must define at least one pollbook client")

seen_hosts = set()
seen_client_ids = set()
for role, hosts in role_groups.items():
    for host in hosts:
        if host in seen_hosts:
            raise SystemExit(f"Inventory host appears in multiple roles: {host}")
        if not re.fullmatch(r"[A-Za-z0-9._-]+", host):
            raise SystemExit(f"Unsupported inventory hostname: {host}")
        seen_hosts.add(host)
        variables = hostvars.get(host, {})

        client_id = ""
        if role == "client":
            client_id = str(variables.get("client_id", ""))
            if not re.fullmatch(r"[0-9]+", client_id):
                raise SystemExit(f"{host} needs a non-negative numeric client_id")
            if client_id in seen_client_ids:
                raise SystemExit(f"Duplicate client_id: {client_id}")
            seen_client_ids.add(client_id)

        sans = variables.get("certificate_sans", []) if role != "client" else []
        if role != "client" and not sans:
            sans = [f"DNS:{host}"]
            address = str(variables.get("ansible_host", ""))
            if address:
                try:
                    ipaddress.ip_address(address)
                    sans.append(f"IP:{address}")
                except ValueError:
                    sans.append(f"DNS:{address}")
        if not isinstance(sans, list):
            raise SystemExit(f"certificate_sans for {host} must be a YAML list")
        for san in sans:
            if not re.fullmatch(r"(?:DNS|IP):[A-Za-z0-9:._-]+", str(san)):
                raise SystemExit(f"Unsupported certificate SAN for {host}: {san}")

        key_prefix = str(variables.get("client_key_file_prefix", "pubkey_"))
        if not re.fullmatch(r"[A-Za-z0-9._-]+", key_prefix):
            raise SystemExit(f"Unsupported client_key_file_prefix: {key_prefix}")

        print("|".join((role, host, client_id, ",".join(map(str, sans)), key_prefix)))
' <<<"${inventory_json}"
)

if [[ ${#inventory_records[@]} -lt 3 ]]; then
    echo "Could not derive the deployment roles from ${inventory_file}." >&2
    exit 1
fi

if [[ "${inventory_check_only}" == true ]]; then
    echo "Validated deployment identities:"
    for record in "${inventory_records[@]}"; do
        IFS='|' read -r role host client_id sans record_key_prefix <<<"${record}"
        if [[ "${role}" == "client" ]]; then
            echo "  ${host}: role=${role}, client_id=${client_id}"
        else
            echo "  ${host}: role=${role}, certificate_sans=${sans}"
        fi
    done
    exit 0
fi

mkdir -p "${ca_dir}" "${devices_dir}" "${shared_dir}" "${client_pubkeys_dir}"

if [[ ! -e "${ca_dir}/ca_key.pem" && ! -e "${ca_dir}/ca_cert.pem" ]]; then
    openssl genrsa -out "${ca_dir}/ca_key.pem" 4096
    openssl req -x509 -new -sha256 -days 1825 \
        -key "${ca_dir}/ca_key.pem" \
        -out "${ca_dir}/ca_cert.pem" \
        -subj "/O=E-Pollbook/CN=E-Pollbook Deployment CA" \
        -addext "basicConstraints = critical,CA:TRUE" \
        -addext "keyUsage = critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier = hash"
elif [[ ! -f "${ca_dir}/ca_key.pem" || ! -f "${ca_dir}/ca_cert.pem" ]]; then
    echo "The CA bundle is incomplete: ca_key.pem and ca_cert.pem must be supplied together." >&2
    exit 1
fi

if ! openssl pkey -in "${ca_dir}/ca_key.pem" -check -noout >/dev/null 2>&1; then
    echo "The CA private key is invalid." >&2
    exit 1
fi

if ! openssl verify -CAfile "${ca_dir}/ca_cert.pem" "${ca_dir}/ca_cert.pem" >/dev/null 2>&1; then
    echo "The CA certificate is invalid or is not self-signed." >&2
    exit 1
fi

if ! cmp -s \
    <(openssl pkey -in "${ca_dir}/ca_key.pem" -pubout 2>/dev/null) \
    <(openssl x509 -in "${ca_dir}/ca_cert.pem" -pubkey -noout 2>/dev/null); then
    echo "The CA private key does not match ca_cert.pem." >&2
    exit 1
fi

generate_identity() {
    local role="$1"
    local host="$2"
    local client_id="$3"
    local sans="$4"
    local device_dir="${devices_dir}/${host}"
    local private_key="${device_dir}/private_key.pem"
    local certificate="${device_dir}/certificate.pem"
    local csr="${device_dir}/certificate.csr"
    local purpose
    local subject

    mkdir -p "${device_dir}"

    if [[ -e "${private_key}" || -e "${certificate}" ]]; then
        if [[ ! -f "${private_key}" || ! -f "${certificate}" ]]; then
            echo "Incomplete existing identity for ${host}; move its directory aside before regenerating." >&2
            exit 1
        fi
        echo "Reusing existing identity for ${host}."
    else
        openssl genrsa -out "${private_key}" 2048

        if [[ "${role}" == "client" ]]; then
            subject="/O=E-Pollbook/OU=Devices/CN=Client ${client_id}/serialNumber=${client_id}"
            openssl req -new -sha256 \
                -key "${private_key}" \
                -out "${csr}" \
                -subj "${subject}" \
                -addext "basicConstraints = critical,CA:FALSE" \
                -addext "keyUsage = critical,digitalSignature,keyEncipherment" \
                -addext "extendedKeyUsage = clientAuth"
        else
            subject="/O=E-Pollbook/OU=Services/CN=${host}"
            openssl req -new -sha256 \
                -key "${private_key}" \
                -out "${csr}" \
                -subj "${subject}" \
                -addext "basicConstraints = critical,CA:FALSE" \
                -addext "keyUsage = critical,digitalSignature,keyEncipherment" \
                -addext "extendedKeyUsage = serverAuth" \
                -addext "subjectAltName = ${sans}"
        fi

        openssl x509 -req -sha256 -days 825 \
            -in "${csr}" \
            -CA "${ca_dir}/ca_cert.pem" \
            -CAkey "${ca_dir}/ca_key.pem" \
            -CAcreateserial \
            -out "${certificate}" \
            -copy_extensions copy
        rm "${csr}"
    fi

    if [[ "${role}" == "client" ]]; then
        purpose="sslclient"
    else
        purpose="sslserver"
    fi
    openssl verify -purpose "${purpose}" \
        -CAfile "${ca_dir}/ca_cert.pem" "${certificate}" >/dev/null

    if [[ "${role}" != "client" ]]; then
        local san_entry
        local san_value
        local -a configured_sans
        IFS=',' read -r -a configured_sans <<<"${sans}"
        for san_entry in "${configured_sans[@]}"; do
            san_value="${san_entry#*:}"
            if [[ "${san_entry}" == DNS:* ]]; then
                if ! openssl x509 -in "${certificate}" -noout -checkhost "${san_value}" >/dev/null; then
                    echo "The certificate for ${host} is missing DNS SAN ${san_value}." >&2
                    exit 1
                fi
            elif ! openssl x509 -in "${certificate}" -noout -checkip "${san_value}" >/dev/null; then
                echo "The certificate for ${host} is missing IP SAN ${san_value}." >&2
                exit 1
            fi
        done
    fi

    if ! cmp -s \
        <(openssl pkey -in "${private_key}" -pubout 2>/dev/null) \
        <(openssl x509 -in "${certificate}" -pubkey -noout 2>/dev/null); then
        echo "The private key and certificate do not match for ${host}." >&2
        exit 1
    fi

    if [[ "${role}" == "client" ]]; then
        local subject_text
        subject_text="$(openssl x509 -in "${certificate}" -subject -noout -nameopt RFC2253)"
        if [[ ! ",${subject_text}," =~ ,CN=Client\ ${client_id}, ]]; then
            echo "The certificate for ${host} does not use CN=Client ${client_id}." >&2
            exit 1
        fi
        openssl pkey -in "${private_key}" -pubout \
            -out "${client_pubkeys_dir}/${client_key_file_prefix}${client_id}.pem"
    elif [[ "${role}" == "checkin" ]]; then
        cp "${certificate}" "${shared_dir}/checkin_certificate.pem"
        openssl pkey -in "${private_key}" -pubout \
            -out "${shared_dir}/checkin_pubkey.pem"
    else
        cp "${certificate}" "${shared_dir}/id_certificate.pem"
        openssl pkey -in "${private_key}" -pubout \
            -out "${shared_dir}/id_pubkey.pem"
    fi
}

client_key_file_prefix=""
for record in "${inventory_records[@]}"; do
    IFS='|' read -r role host client_id sans record_key_prefix <<<"${record}"
    if [[ -z "${client_key_file_prefix}" ]]; then
        client_key_file_prefix="${record_key_prefix}"
    elif [[ "${client_key_file_prefix}" != "${record_key_prefix}" ]]; then
        echo "All deployment hosts must use the same client_key_file_prefix." >&2
        exit 1
    fi
    generate_identity "${role}" "${host}" "${client_id}" "${sans}"
done

cp "${ca_dir}/ca_cert.pem" "${shared_dir}/ca_cert.pem"

echo "Prepared identities for every host in ${inventory_file}."
echo "The CA private key remains only at ${ca_dir}/ca_key.pem; keep it offline and backed up."
echo "Review certificate SANs, then run: ansible-playbook deploy.yml --check --diff"
