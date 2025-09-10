import socket, ssl, json, base64, time
from pathlib import Path
from collections import OrderedDict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import configparser

SERVER_KEYS_DIR = Path("server_keys")
CHECKIN_PUBKEY_FILE = SERVER_KEYS_DIR / "checkin_pubkey.pem"

# ----- exact-bytes JSON (match nlohmann insertion order + compact separators) -----
def dump(obj: OrderedDict) -> bytes:
    # nlohmann::json.dump() defaults to no extra spaces; separators=(",", ":") matches that.
    # Do NOT sort keys; preserve insertion order.
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

# ----- RSA helpers -----
class RSASigner:
    def __init__(self, pem_private_key_path: str):
        with open(pem_private_key_path, "rb") as f:
            self.key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    def sign(self, msg: bytes) -> bytes:
        return self.key.sign(msg, padding.PKCS1v15(), hashes.SHA256())

class RSAVerifier:
    def __init__(self, pem_public_key_path: str):
        with open(pem_public_key_path, "rb") as f:
            self.key = serialization.load_pem_public_key(f.read())
    def verify_b64(self, msg: bytes, sig_b64: str) -> bool:
        try:
            self.key.verify(base64.b64decode(sig_b64), msg, padding.PKCS1v15(), hashes.SHA256())
            return True
        except InvalidSignature:
            return False

# ----- TLS + key harvest (reuse your earlier approach) -----
def tls_connect_and_harvest_pubkey(ca_cert, cert, key, host, port):
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_cert)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    raw = socket.create_connection((host, port), timeout=10)
    ssock = ctx.wrap_socket(raw, server_hostname=host)
    ssock.settimeout(10)

    der = ssock.getpeercert(binary_form=True)
    pub = x509.load_der_x509_certificate(der).public_key()
    pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    CHECKIN_PUBKEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CHECKIN_PUBKEY_FILE.with_suffix(".pem.tmp"), "wb") as f:
        f.write(pem)
    CHECKIN_PUBKEY_FILE.with_suffix(".pem.tmp").replace(CHECKIN_PUBKEY_FILE)
    return ssock

# ----- len-prefixed I/O -----
def _read_line(sock: ssl.SSLSocket) -> bytes:
    buf = bytearray()
    while not buf.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Socket closed while reading line")
        buf.extend(chunk)
    return bytes(buf[:-1])

def _recv_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed while reading body")
        buf.extend(chunk)
    return bytes(buf)

def send_len_prefixed(sock: ssl.SSLSocket, obj_bytes: bytes):
    sock.sendall(str(len(obj_bytes)).encode() + b"\n" + obj_bytes + b"\n")

def recv_len_prefixed(sock: ssl.SSLSocket) -> dict:
    n = int(_read_line(sock))
    body = _recv_exact(sock, n)
    # optional trailing newline is fine
    return json.loads(body.decode("utf-8"))

# ===== BUILD & SEND TICKET REQUEST (matches TicketRequest::ToJson) =====
def build_ticket_request_body(client_id: int, ticket: str, pin: int) -> OrderedDict:
    # Order: client_id, timestamp, ticket, pin
    return OrderedDict([
        ("client_id", int(client_id)),
        ("timestamp", int(time.time() * 1000)),
        ("ticket", ticket),
        ("pin", int(pin)),
    ])

def make_ticket_request(signer: RSASigner, body: OrderedDict) -> bytes:
    body_bytes = dump(body)
    sig = signer.sign(body_bytes)
    req = OrderedDict([
        ("body", body),                      # nested object keeps insertion order
        ("signature", base64.b64encode(sig).decode("ascii")),
    ])
    return dump(req)

# ===== VERIFY TICKET RESPONSE (matches TicketResponse::ToJson) =====
def response_body_bytes_like_cpp(resp_body: dict) -> bytes:
    # Expected order: approved, last_name, first_name, middle_name, voter_unique_id, pin, secret
    # (Their C++ ToJson writes "pin" twice; final value is the same. We keep a single "pin".)
    ordered = OrderedDict([
        ("approved", bool(resp_body["approved"])),
        ("last_name", resp_body["last_name"]),
        ("first_name", resp_body["first_name"]),
        ("middle_name", resp_body["middle_name"]),
        ("voter_unique_id", int(resp_body["voter_unique_id"])),
        ("pin", int(resp_body["pin"])),
        ("secret", resp_body["secret"]),
    ])
    return dump(ordered)

def verify_ticket_flow(
    ca_cert: str, client_cert: str, client_key: str,
    checkin_host: str, checkin_port: int,
    client_signing_key: str,           # same as client_key typically
    client_id: int, ticket: str, pin: int
):
    # Connect + harvest check-in pubkey
    sock = tls_connect_and_harvest_pubkey(ca_cert, client_cert, client_key, checkin_host, checkin_port)

    try:
        signer = RSASigner(client_signing_key)
        body = build_ticket_request_body(client_id, ticket, pin)
        wire = make_ticket_request(signer, body)

        send_len_prefixed(sock, wire)
        resp = recv_len_prefixed(sock)

        # Verify service signature
        verifier = RSAVerifier(str(CHECKIN_PUBKEY_FILE))
        sig_field = resp.get("signature")  # TicketResponse uses "signature"
        if not sig_field:
            return {"ok": False, "error": "missing_signature_field", "raw": resp}

        msg_bytes = response_body_bytes_like_cpp(resp["body"])
        if not verifier.verify_b64(msg_bytes, sig_field):
            return {"ok": False, "error": "bad_signature_from_checkin_service", "raw": resp}

        return {
            "ok": bool(resp["body"].get("approved", False)),
            "secret": resp["body"].get("secret"),
            "first_name": resp["body"].get("first_name"),
            "middle_name": resp["body"].get("middle_name"),
            "last_name": resp["body"].get("last_name"),
            "voter_unique_id": resp["body"].get("voter_unique_id"),
            "raw": resp,
        }
    finally:
        try: sock.close()
        except: pass




def main():
    cfg = configparser.ConfigParser()
    cfg.read("docker-test-deployment/client1/client_config.ini")

    ca_cert = cfg["Security"]["ca_cert"]
    client_cert = cfg["Security"]["local_cert"]
    client_key = cfg["Security"]["private_key"]
    signing_key = cfg["Security"]["private_key"]

    host = cfg["Basic"]["checkin_service_host"]
    port = int(cfg["Basic"]["checkin_service_port"])
    client_id = int(cfg["Basic"]["client_id"])

    # ticket + pin
    ticket = input("Ticket: ").strip()
    pin = int(input("Enter PIN: ").strip())

    result = verify_ticket_flow(
        ca_cert=ca_cert,
        client_cert=client_cert,
        client_key=client_key,
        checkin_host=host,
        checkin_port=port,
        client_signing_key=signing_key,
        client_id=client_id,
        ticket=ticket,
        pin=pin,
    )

    if result["ok"]:
        print("Ticket approved")
        print(f"Voter: {result['first_name']} {result['middle_name']} {result['last_name']}")
        print("Secret:", result["secret"])
    else:
        print("Ticket invalid:", result.get("error"))
        print("Raw response:", result["raw"])

if __name__ == "__main__":
    main()

