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
TRUSTED_LAT_FILE = Path("../../metrics/trusted_latencies.csv")

# ---------------- JSON helpers ----------------

def dump(obj: OrderedDict) -> bytes:
    """Stable, compact JSON encoding matching nlohmann behavior."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

# ---------------- Config ----------------

def load_config(cfg_str: str) -> configparser.ConfigParser:
    p = Path(cfg_str)
    candidates = [p if p.is_absolute() else Path.cwd() / p, Path(__file__).parent / p]

    for c in candidates:
        cfg = configparser.ConfigParser(
            interpolation=configparser.ExtendedInterpolation(),
            defaults=os.environ,
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

# ---------------- RSA helpers ----------------

class RSASigner:
    def __init__(self, pem_private_key_path: str):
        with open(pem_private_key_path, "rb") as f:
            self.key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

    def sign(self, msg: bytes) -> bytes:
        return self.key.sign(msg, padding.PKCS1v15(), hashes.SHA256())


class RSAVerifier:
    def __init__(self, pem_or_path):
        if isinstance(pem_or_path, (bytes, bytearray)):
            pem_data = pem_or_path
        else:
            with open(pem_or_path, "rb") as f:
                pem_data = f.read()
        self.public_key = serialization.load_pem_public_key(pem_data)
        self._buffer = bytearray()

    def init(self):
        self._buffer.clear()

    def add_bytes(self, data: bytes):
        self._buffer.extend(data)

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

# ---------------- TLS: context + one-shot connections ----------------

def make_ssl_context(ca_cert: str, cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_cert)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx

def get_checkin_pubkey_pem(ctx: ssl.SSLContext, host: str, port: int) -> bytes:
    """
    Do a single handshake to fetch the checkin server's public key.
    Close the connection immediately after.
    """
    raw = socket.create_connection((host, port), timeout=10)
    try:
        ssock = ctx.wrap_socket(raw, server_hostname=host)
        ssock.settimeout(10)
        der = ssock.getpeercert(binary_form=True)
    finally:
        try:
            raw.close()
        except Exception:
            pass

    cert = x509.load_der_x509_certificate(der)
    pub = cert.public_key()
    pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return pem

def make_checkin_connection(ctx: ssl.SSLContext, host: str, port: int) -> ssl.SSLSocket:
    """
    Create a fresh TLS connection to checkin for one verify call.
    The server-side currently behaves one-request-per-connection.
    """
    raw = socket.create_connection((host, port), timeout=10)
    ssock = ctx.wrap_socket(raw, server_hostname=host)
    ssock.settimeout(10)
    return ssock

# ---------------- CSV logging ----------------

def _trusted_csv_append(
    row,
    header=("phase", "latency_ms", "approved", "meta_json"),
):
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

# ---------------- len-prefixed I/O ----------------

def _read_line(sock) -> bytes:
    buf = bytearray()
    while not buf.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Socket closed while reading line")
        buf.extend(chunk)
    return bytes(buf[:-1])  # strip trailing '\n'

def _recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed while reading body")
        buf.extend(chunk)
    return bytes(buf)

def send_ticket(sock, obj_bytes: bytes):
    sock.sendall(str(len(obj_bytes)).encode() + b"\n" + obj_bytes + b"\n")

def recv_response(sock) -> dict:
    line = _read_line(sock)
    try:
        n = int(line)
    except ValueError:
        # plain JSON line
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

# ---------------- Ticket building ----------------

def build_ticket_body(client_id: int, ticket: str, pin: int) -> OrderedDict:
    return OrderedDict(
        [
            ("client_id", int(client_id)),
            ("pin", int(pin)),
            ("ticket", ticket),
            ("timestamp", int(time.time() * 1000)),
        ]
    )

def make_ticket_request(signer: RSASigner, body: OrderedDict) -> bytes:
    body_bytes = dump(body)
    sig = signer.sign(body_bytes)
    req = OrderedDict(
        [
            ("body", body),
            ("signature", base64.b64encode(sig).decode("ascii")),
        ]
    )
    return dump(req)

# ---------------- Core verify flow (per ticket) ----------------

def verify_ticket_flow(
    ssl_ctx: ssl.SSLContext,
    host: str,
    port: int,
    signer: RSASigner,
    service_verifier: RSAVerifier,
    client_id: int,
    ticket: str,
    pin: int,
):
    # New TLS connection for this verify
    sock = make_checkin_connection(ssl_ctx, host, port)
    try:
        body = build_ticket_body(client_id, ticket, pin)
        request = make_ticket_request(signer, body)

        send_ticket(sock, request)
        resp = recv_response(sock)
        print("response received")

        # Verify service signature
        service_verifier.init()
        service_verifier.add_bytes(dump(resp["body"]))
        approved = service_verifier.finalize(resp["signature"])
        if not approved:
            return {
                "ok": False,
                "error": "bad_signature_from_checkin_service",
                "raw": resp,
            }

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
        try:
            sock.close()
        except Exception:
            pass

# ---------------- Main server loop ----------------

def main():
    parser = argparse.ArgumentParser(prog="client")
    parser.add_argument("cfg_file", type=Path)
    args = parser.parse_args()

    cfg = load_config(args.cfg_file)

    ca_cert = cfg["Security"]["ca_cert"]
    client_cert = cfg["Security"]["local_cert"]
    client_key = cfg["Security"]["private_key"]
    signing_key = cfg["Security"]["private_key"]

    host = cfg["Basic"]["checkin_service_host"]
    port = int(cfg["Basic"]["checkin_service_port"])
    client_id = int(cfg["Basic"]["client_id"])

    listen_host = cfg["Basic"]["listen_host"]
    listen_port = int(cfg["Basic"]["listen_port"])

    # Build reusable pieces once
    ssl_ctx = make_ssl_context(ca_cert, client_cert, client_key)
    checkin_pubkey_pem = get_checkin_pubkey_pem(ssl_ctx, host, port)
    service_verifier = RSAVerifier(checkin_pubkey_pem)
    signer = RSASigner(signing_key)

    with socket.create_server((listen_host, listen_port), reuse_port=True) as srv:
        print(f"[trusted] listening on {listen_host}:{listen_port}")
        while True:
            try:
                conn, addr = srv.accept()
                with conn:
                    try:
                        msg = recv_response(conn)

                        ticket = msg.get("ticket")
                        pin = msg.get("pin")
                        cid = client_id

                        if not isinstance(ticket, str) or not ticket:
                            send_ticket(
                                conn,
                                dump({"received": False, "error": "empty_ticket"}),
                            )
                            continue

                        try:
                            pin = int(pin)
                        except Exception:
                            send_ticket(
                                conn,
                                dump({"received": False, "error": "bad_pin"}),
                            )
                            continue

                        t0 = time.perf_counter()
                        result = verify_ticket_flow(
                            ssl_ctx=ssl_ctx,
                            host=host,
                            port=port,
                            signer=signer,
                            service_verifier=service_verifier,
                            client_id=cid,
                            ticket=ticket,
                            pin=pin,
                        )
                        elapsed_ms = (time.perf_counter() - t0) * 1000.0

                        print(
                            f"[trusted] latency={elapsed_ms:.3f} ms (about to append)"
                        )
                        _trusted_csv_append(
                            [
                                "trusted_verify",
                                f"{elapsed_ms:.3f}",
                                bool(result.get("ok", False)),
                                json.dumps({"client_id": cid}),
                            ]
                        )

                        if result["ok"]:
                            print(
                                f"[trusted] approved from {addr}: "
                                f"{result['first_name']} {result['middle_name']} {result['last_name']}"
                            )
                        else:
                            print(
                                f"[trusted] rejected from {addr}: "
                                f"{result.get('error')}"
                            )

                        send_ticket(
                            conn,
                            dump(
                                {
                                    "received": True,
                                    "approved": bool(result["ok"]),
                                }
                            ),
                        )

                    except Exception as e:
                        try:
                            send_ticket(
                                conn,
                                dump({"received": False, "error": str(e)}),
                            )
                        except Exception:
                            pass
            except KeyboardInterrupt:
                print("Shutting down cleanly")
                sys.exit(0)

if __name__ == "__main__":
    main()

