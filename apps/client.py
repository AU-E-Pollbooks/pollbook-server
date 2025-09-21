import socket
import csv
import argparse
import os
import time
import json
import base64
import ssl
import configparser
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SERVER_KEYS_DIR = Path("server_keys")
ID_PUBKEY_FILE = SERVER_KEYS_DIR / "id_pubkey.pem"
CHECKIN_PUBKEY_FILE = SERVER_KEYS_DIR / "checkin_pubkey.pem"



def load_config(cfg_str: str) -> configparser.ConfigParser:
    p = Path(cfg_str)
    candidates = [p if p.is_absolute() else Path.cwd() / p,
                  Path(__file__).parent / p]

    for c in candidates:
        # Seed defaults with environment so ${TRUSTED_NAME} resolves
        cfg = configparser.ConfigParser(
            interpolation=configparser.ExtendedInterpolation(),
            defaults=os.environ
        )
        if cfg.read(c):
            # resolve Security paths relative to the config file
            if "Security" in cfg:
                base = c.parent
                for key in ("local_cert", "private_key", "ca_cert"):
                    if key in cfg["Security"]:
                        path = Path(cfg["Security"][key])
                        if not path.is_absolute():
                            cfg["Security"][key] = str((base / path).resolve())
            return cfg

    tried = " | ".join(str(c.resolve()) for c in candidates)
    raise FileNotFoundError(f"Could not read config. Tried: {tried}")

def ensure_parent_dir(p: Path):
    p.parent.mkdir(parents=True, exist_ok=True)

def extract_and_store_peer_pubkey(ssock: ssl.SSLSocket, out_path: Path):
    # Grab the peer certificate from the established TLS session
    der_cert = ssock.getpeercert(binary_form=True)
    if not der_cert:
        raise RuntimeError("TLS peer did not present a certificate")
    cert = x509.load_der_x509_certificate(der_cert)
    pubkey = cert.public_key()

    pem = pubkey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    ensure_parent_dir(out_path)

    # Write atomically where possible
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(pem)
    tmp.replace(out_path)

def create_tls_context(certfile: str, keyfile: str, cafile: str) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


def create_tls_sockets(cfg):
    context = create_tls_context(
        cfg["Security"]["local_cert"],
        cfg["Security"]["private_key"],
        cfg["Security"]["ca_cert"],
    )

    voter_socket = tls_handshake(
        cfg["Basic"]["id_service_host"],
        int(cfg["Basic"]["id_service_port"]),
        context,
        "VoterServer",
    )
    # Save ID service pubkey
    extract_and_store_peer_pubkey(voter_socket, ID_PUBKEY_FILE)

    checkin_socket = tls_handshake(
        cfg["Basic"]["checkin_service_host"],
        int(cfg["Basic"]["checkin_service_port"]),
        context,
        "CheckinServer",
    )
    # Save Checkin service pubkey
    extract_and_store_peer_pubkey(checkin_socket, CHECKIN_PUBKEY_FILE)

    return voter_socket, checkin_socket


def tls_handshake(host: str, port: int, context: ssl.SSLContext, label: str) -> ssl.SSLSocket:
    sock = socket.create_connection((host, port))
    ssock = context.wrap_socket(sock, server_hostname=host)
    print(f"Handshake successful with {label} ({host}:{port})")
    return ssock




class RSASigner:
    def __init__(self, private_key_path: str):
        with open(private_key_path, "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )

    def sign(self, message: bytes) -> bytes:
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(message)
        digest = hasher.finalize()
        return self.private_key.sign(
            digest, padding.PKCS1v15(), hashes.SHA256()
        )


class RSAVerifier:
    def __init__(self, public_key_path: str):
        with open(public_key_path, "rb") as f:
            self.public_key = serialization.load_pem_public_key(f.read())
        self._buffer = bytearray()

    def init(self):
        self._buffer.clear()

    def add_bytes(self, data: Union[bytes, bytearray]):
        self._buffer.extend(data)

    def finalize(self, signature: Union[bytes, bytearray]) -> bool:
        try:
            self.public_key.verify(
                signature, self._buffer, padding.PKCS1v15(), hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


def build_voter_id_request(cfg, first_name, middle_name, last_name, voter_id):

    dummy_bytes = bytes([
        0x1a, 0x1b, 0x1c, 0x1d, 0x2a, 0x2b, 0x2c, 0x2d,
        0xff, 0xff, 0xff, 0xff, 0x1, 0x1, 0x1, 0x1,
        0x1a, 0x1b, 0x1c, 0x1d, 0x2a, 0x2b, 0x2c, 0x2d
    ])
    voter_id_raw = voter_id.to_bytes(4, "little") + dummy_bytes
    body = {
        "client_id_num": int(cfg["Basic"]["client_id"]),
        "timestamp": int(time.time() * 1000),
        "last_name": last_name,
        "middle_name": middle_name,
        "first_name": first_name,
        "voter_id_data": base64.b64encode(voter_id_raw).decode("ascii"),
    }
    private_key_path = cfg["Security"]["private_key"]
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )
    signature = private_key.sign(
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return {
        "body": body,
        "client_signature": base64.b64encode(signature).decode("ascii"),
    }

def send_len_prefixed_bytes(sock: socket.socket, payload: bytes):
    sock.sendall(str(len(payload)).encode() + b"\n" + payload + b"\n")


def get_pin_for_id(csv_path: str, voter_id: int) -> int:
    """Look up PIN by voter_unique_id in the CSV."""
    p = Path(csv_path)
    if not p.is_absolute():
        p = Path.cwd() / p
    with p.open(newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        # Expect headers: id,pin
        for row in r:
            if int(row["UID"]) == voter_id:
                return int(row["PIN"])
    raise KeyError(f"PIN not found for id {voter_id}")

def send_ticket_to_trusted(cfg, ticket: str, client_id: int, voter_id: int):
    host = cfg["Basic"]["ticket_sink_host"]
    port = int(cfg["Basic"]["ticket_sink_port"])

     # Load PIN from CSV (set Basic.pin_csv in your INI)
    pin_csv = cfg["Basic"].get("pin_csv", "").strip()
    pin = get_pin_for_id(pin_csv, voter_id) if pin_csv else None

    payload = {
        "client_id": int(client_id),
        "pin": int(pin) if pin is not None else None,
        "ticket": ticket,
        "timestamp": int(time.time() * 1000),
    }
    wire = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    with socket.create_connection((host, port), timeout=5) as s:
        send_len_prefixed_bytes(s, wire)
        # optional: read a small ack (len-prefixed JSON)
        try:
            s.settimeout(3)
            # reuse your _read_line / _recv_exact if you want a reply
            ack_len = b""
            while not ack_len.endswith(b"\n"):
                chunk = s.recv(1)
                if not chunk:
                    break
                ack_len += chunk
            if ack_len:
                n = int(ack_len.strip())
                ack = b""
                while len(ack) < n:
                    chunk = s.recv(n - len(ack))
                    if not chunk:
                        break
                    ack += chunk
                # You could log this if you like:
                # print("Trusted ack:", ack.decode())
        except Exception:
            pass

def send_request(sock: ssl.SSLSocket, request: dict):
    msg = json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sock.sendall(f"{len(msg)}\n".encode() + msg + b"\n")

def receive_voter_id(socket: ssl.SSLSocket) -> dict:
    data = b""
    while not data.endswith(b"\n"):
        chunk = socket.recv(1)
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    response_str = data.strip()
    try:
        payload = json.loads(response_str.decode())
        return payload
    except Exception as e:
        print("Failed to parse VerifiedVoterID:", e)
        raise


def receive_checkin_response(sock: ssl.SSLSocket) -> dict: 
    def read_line(): 
        line = b"" 
        while not line.endswith(b"\n"): 
            chunk = sock.recv(1) 
            if not chunk: 
                raise ConnectionError("Socket closed while reading line") 
            line += chunk 
        return line.strip() 

    length_line = read_line() 
    try: 
        msg_len = int(length_line) 
    except ValueError: 
        raise ValueError(f"Invalid length prefix: {length_line}") 
    body = read_line() 
    try: 
        payload = json.loads(body.decode()) 
    except ValueError: 
        raise ValueError(f"Invalid length prefix: {length_line}") 
    return payload

def verify_signature(public_key_path, data: dict, sig_b64: str):
    verifier = RSAVerifier(public_key_path)
    verifier.init()
    verifier.add_bytes(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
    return verifier.finalize(base64.b64decode(sig_b64))


def main():

    parser = argparse.ArgumentParser(prog='client')
    parser.add_argument('cfg_file', type=Path)
    args = parser.parse_args()

    config = load_config(args.cfg_file)
    signer = RSASigner(config["Security"]["private_key"])
    voter_socket, checkin_socket = create_tls_sockets(config)

    first_name = input("First Name: ")
    middle_name = input("Middle Name: ")
    last_name = input("Last Name: ")
    voter_id = int(input("Voter ID: "))
    voter_id_request = build_voter_id_request(config, first_name, middle_name, last_name, voter_id)
    send_request(voter_socket, voter_id_request)

    response = receive_voter_id(voter_socket)
    # ID service signature verification
    vvid_data = {
        "presented_id": response["presented_id"],
        "voter_unique_id": response["voter_unique_id"],
    }
    if verify_signature(str(ID_PUBKEY_FILE), vvid_data, response["id_service_signature"]):
        print("Valid signature from ID server")
    else:
        print("Invalid signature from ID server")
        return

    timestamp = int(time.time() * 1000)
    checkin_body = {
        "client_id_num": int(config["Basic"]["client_id"]),
        "timestamp": timestamp,
        "first_name": first_name,
        "middle_name": middle_name,
        "last_name": last_name,
        "voter_unique_id": response["voter_unique_id"],
        "verified_id_message": response
    }

    private_key_path = config["Security"]["private_key"]
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )
    checkin_sig = private_key.sign(
        json.dumps(checkin_body, sort_keys=True, separators=(",", ":")).encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    checkin_request = {
        "body": checkin_body,
        "client_signature": base64.b64encode(checkin_sig).decode()
    }
    send_request(checkin_socket, checkin_request)

    checkin_resp = receive_checkin_response(checkin_socket)
    # After verifying check-in response signature:
    if verify_signature(str(CHECKIN_PUBKEY_FILE), checkin_resp["body"], checkin_resp["checkin_service_signature"]):
        print("Valid checkin response signature")
        ticket = checkin_resp["body"]["ticket"]
        
        # send to trusted client
        send_ticket_to_trusted(config, ticket, int(config["Basic"]["client_id"]), voter_id)
        print("Ticket Sent")
    else:
        print("Invalid signature in checkin response")


if __name__ == "__main__":
    main()

