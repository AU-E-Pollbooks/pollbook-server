import socket, ssl, json, base64, time
import os, sys, argparse, csv
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
TRUSTED_LAT_FILE = Path("trusted_latencies.csv")

# ----- exact-bytes JSON (match nlohmann insertion order + compact separators) -----
def dump(obj: OrderedDict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def load_config(cfg_str: str) -> configparser.ConfigParser:
    p = Path(cfg_str)
    candidates = [p if p.is_absolute() else Path.cwd() / p, Path(__file__).parent / p]

    for c in candidates:
        cfg = configparser.ConfigParser(
            interpolation=configparser.ExtendedInterpolation(),
            defaults=os.environ,  # <-- pulls from env (e.g., TRUSTED_NAME)
        )
        if cfg.read(c):
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
            self.public_key = serialization.load_pem_public_key(f.read())
        self._buffer = bytearray()
    def init(self): self._buffer.clear()
    def add_bytes(self, data: bytes): self._buffer.extend(data)
    def finalize(self, signature_b64: str) -> bool:
        try:
            self.public_key.verify(
                base64.b64decode(signature_b64),
                self._buffer,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False

# ----- TLS + key harvest (reuse your earlier approach) -----
def make_handshake(ca_cert, cert, key, host, port):
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

def _trusted_csv_append(row, header=("phase","latency_ms","approved","meta_json")):
    TRUSTED_LAT_FILE.parent.mkdir(parents=True, exist_ok=True)
    new = not TRUSTED_LAT_FILE.exists()
    with TRUSTED_LAT_FILE.open("a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(header)
        w.writerow(row)
        f.flush()
        os.fsync(f.fileno())
    print(f"[trusted] wrote row to {TRUSTED_LAT_FILE}")
    sys.stdout.flush()
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

# def send_ticket(sock: ssl.SSLSocket, obj_bytes: bytes):
def send_ticket(sock: socket.socket, obj_bytes: bytes):
    sock.sendall(str(len(obj_bytes)).encode() + b"\n" + obj_bytes + b"\n")

# def recv_response(sock: ssl.SSLSocket) -> dict:
def recv_response(sock: socket.socket) -> dict:
    # read first line
    line = _read_line(sock)  # strips trailing '\n'
    # Try len-prefixed first
    try:
        n = int(line)
    except ValueError:
        # Not a length → it's a full JSON line
        return json.loads(line.decode("utf-8"))
    else:
        body = _recv_exact(sock, n)
        # optional trailing newline
        try:
            sock.settimeout(0.01)
            try:
                if sock.recv(1, socket.MSG_PEEK) == b"\n":
                    sock.recv(1)
            except Exception:
                pass
        finally:
            sock.settimeout(None)
        return json.loads(body.decode("utf-8"))

# ===== BUILD & SEND TICKET REQUEST (matches TicketRequest::ToJson) =====
def build_ticket_body(client_id: int, ticket: str, pin: int) -> dict:
    return {
        "client_id": int(client_id),
        "pin": int(pin),
        "ticket": ticket,
        "timestamp": int(time.time() * 1000),
    }

def make_ticket_request(signer: RSASigner, body: OrderedDict) -> bytes:
    body_bytes = dump(body)
    sig = signer.sign(body_bytes)
    req = OrderedDict([
        ("body", body),                     # object with stable key order
        ("signature", base64.b64encode(sig).decode("ascii")),
    ])
    return dump(req)


def verify_ticket_flow(
    ca_cert: str, client_cert: str, client_key: str,
    checkin_host: str, checkin_port: int,
    client_signing_key: str,           # same as client_key typically
    client_id: int, ticket: str, pin: int
):
    # Connect + harvest check-in pubkey
    sock = make_handshake(ca_cert, client_cert, client_key, checkin_host, checkin_port)

    try:
        signer = RSASigner(client_signing_key)
        body = build_ticket_body(client_id, ticket, pin)
        # sig = signer.sign(dump(body))  # PKCS1v15+SHA256

        request = make_ticket_request(signer, body)

        send_ticket(sock, request)
        resp = recv_response(sock)
        print("response received")

        # Verify service signature
        verifier = RSAVerifier(str(CHECKIN_PUBKEY_FILE))
        verifier.init()
        verifier.add_bytes(dump(resp["body"]))
        approved = verifier.finalize(resp["signature"])
        if not approved:
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
    parser = argparse.ArgumentParser(prog='client')
    parser.add_argument('cfg_file', type=Path)
    args = parser.parse_args()

    cfg = configparser.ConfigParser()
    cfg = load_config(args.cfg_file)
    # cfg.read("client_config.ini")

    ca_cert = cfg["Security"]["ca_cert"]
    client_cert = cfg["Security"]["local_cert"]
    client_key = cfg["Security"]["private_key"]
    signing_key = cfg["Security"]["private_key"]

    host = cfg["Basic"]["checkin_service_host"]
    port = int(cfg["Basic"]["checkin_service_port"])
    client_id = int(cfg["Basic"]["client_id"])


    listen_host = cfg["Basic"]["listen_host"]
    listen_port = int(cfg["Basic"]["listen_port"])

    # Simple TCP server that waits for tickets
    with socket.create_server((listen_host, listen_port), reuse_port=True) as srv:
        print(f"[trusted] listening on {listen_host}:{listen_port}")
        while True:
            try:
                conn, addr = srv.accept()
                with conn:
                    try:
                        msg = recv_response(conn)

                        # --- input validation
                        ticket = msg.get("ticket")
                        pin = msg.get("pin")
                        cid = client_id 

                        if not isinstance(ticket, str) or not ticket:
                            send_ticket(conn, dump({"received": False, "error": "empty_ticket"}))
                            continue

                        try:
                            pin = int(pin)
                        except Exception:
                            send_ticket(conn, dump({"received": False, "error": "bad_pin"}))
                            continue

                        # --- call the check-in service only after validation ---
                        t0 = time.perf_counter()
                        result = verify_ticket_flow(
                            ca_cert=ca_cert,
                            client_cert=client_cert,
                            client_key=client_key,
                            checkin_host=host,
                            checkin_port=port,
                            client_signing_key=signing_key,
                            client_id=cid,
                            ticket=ticket,
                            pin=pin,
                        )
                        elapsed_ms = (time.perf_counter() - t0) * 1000.0

                        print(f"[trusted] latency={elapsed_ms:.3f} ms (about to append)")  # debug
                        _trusted_csv_append([
                            "trusted_verify",
                            f"{elapsed_ms:.3f}",
                            bool(result.get("ok", False)),
                            json.dumps({"client_id": cid})
                        ])

                        if result["ok"]:
                            print(f"[trusted] approved from {addr}: {result['first_name']} {result['middle_name']} {result['last_name']}")
                        else:
                            print(f"[trusted] rejected from {addr}: {result.get('error')}")

                        send_ticket(conn, dump({"received": True, "approved": bool(result["ok"])}))

                    except Exception as e:
                        try:
                            send_ticket(conn, dump({"received": False, "error": str(e)}))
                        except Exception:
                            pass
            except KeyboardInterrupt:
                print("Shutting down cleanly")
                sys.exit(0)
if __name__ == "__main__":
    main()

