import socket, csv, argparse, os, time, random
import json, base64, ssl, configparser, sys
from pathlib import Path
from typing import Union, Tuple, Dict, Any, List

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SERVER_KEYS_DIR = Path("server_keys")
ID_PUBKEY_FILE = SERVER_KEYS_DIR / "id_pubkey.pem"
CHECKIN_PUBKEY_FILE = SERVER_KEYS_DIR / "checkin_pubkey.pem"

LAT_FILE = Path("../../metrics/untrusted_latencies.csv")


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


def tls_handshake(host: str, port: int, context: ssl.SSLContext, label: str) -> ssl.SSLSocket:
    sock = socket.create_connection((host, port))
    ssock = context.wrap_socket(sock, server_hostname=host)
    print(f"Handshake successful with {label} ({host}:{port})")
    return ssock


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


def build_voter_id_request(cfg, first_name, middle_name, last_name, voter_id) -> Dict[str, Any]:
    # In the real system this would be derived from an ID card scan + auxiliary data.
    # Here we continue to use a dummy payload so we can focus on protocol behavior.
    dummy_bytes = bytes([
        0x1A, 0x1B, 0x1C, 0x1D, 0x2A, 0x2B, 0x2C, 0x2D,
        0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x01, 0x01, 0x01,
        0x1A, 0x1B, 0x1C, 0x1D, 0x2A, 0x2B, 0x2C, 0x2D,
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
        for row in r:
            if int(row["UID"]) == voter_id:
                return int(row["PIN"])
    raise KeyError(f"PIN not found for id {voter_id}")


def send_ticket_to_trusted(cfg, ticket: str, client_id: int, voter_id: int, phase_label: str = "trusted_sink"):
    """
    Send ticket + PIN to the trusted sink, mimicking the trusted client behavior.

    By varying 'voter_id' relative to the ticket's true owner, we can simulate the
    ticket-substitution attack from the paper.
    """
    host = cfg["Basic"]["ticket_sink_host"]
    port = int(cfg["Basic"]["ticket_sink_port"])

    pin_csv = cfg["Basic"].get("pin_csv", "").strip()
    pin = get_pin_for_id(pin_csv, voter_id) if pin_csv else None

    payload = {
        "client_id": int(client_id),
        "pin": int(pin) if pin is not None else None,
        "ticket": ticket,
        "timestamp": int(time.time() * 1000),
    }
    wire = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    t0 = time.perf_counter()
    with socket.create_connection((host, port), timeout=5) as s:
        send_len_prefixed_bytes(s, wire)
        try:
            s.settimeout(3)
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
        except Exception:
            pass
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    _csv_append(
        LAT_FILE,
        [phase_label, f"{elapsed_ms:.3f}", True, json.dumps({"voter_id": voter_id})],
        header=["phase", "latency_ms", "ok", "meta_json"],
    )


def _csv_append(path: Path, row: List[Any], header: List[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists()
    with path.open("a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(header)
        w.writerow(row)


def send_request(sock: ssl.SSLSocket, request: Dict[str, Any]):
    msg = json.dumps(request, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sock.sendall(f"{len(msg)}\n".encode() + msg + b"\n")


def timed_lenpref_request(sock, payload: Dict[str, Any], recv_fn, label: str, extra: Dict[str, Any] = None):
    start = time.perf_counter()
    send_request(sock, payload)
    resp = recv_fn(sock)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    _csv_append(
        LAT_FILE,
        [label, f"{elapsed_ms:.3f}", bool(resp), json.dumps(extra or {})],
        header=["phase", "latency_ms", "ok", "meta_json"],
    )
    return resp


def receive_voter_id(sock: ssl.SSLSocket) -> Dict[str, Any]:
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
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


def receive_checkin_response(sock: ssl.SSLSocket) -> Dict[str, Any]:
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
    body = b""
    while len(body) < msg_len:
        chunk = sock.recv(msg_len - len(body))
        if not chunk:
            raise ConnectionError("Socket closed while reading body")
        body += chunk
    try:
        payload = json.loads(body.decode())
    except ValueError:
        raise
    return payload


def verify_signature(public_key_path: str, data: Dict[str, Any], sig_b64: str) -> bool:
    verifier = RSAVerifier(public_key_path)
    verifier.init()
    verifier.add_bytes(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
    return verifier.finalize(base64.b64decode(sig_b64))


def load_voters_csv(csv_path: Path):
    """Return a list of voter dicts from voters.csv."""
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        voters = []
        for row in reader:
            voters.append({
                "id": int(row["UID"]),
                "first_name": row["First Name"],
                "middle_name": row["Middle Name"],
                "last_name": row["Last Name"],
            })
        return voters


def honest_flow(cfg, voter_sock, checkin_sock, voter) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Honest protocol execution: ID -> check-in -> ticket to trusted sink.
    Returns (id_response, checkin_response).
    """
    voter_id = voter["id"]
    fn, mn, ln = voter["first_name"], voter["middle_name"], voter["last_name"]

    # ---- ID request
    id_req = build_voter_id_request(cfg, fn, mn, ln, voter_id)
    id_resp = timed_lenpref_request(
        voter_sock, id_req, receive_voter_id, "id_service",
        extra={"voter_id": voter_id, "mode": "honest"},
    )

    # Verify ID server signature (expected to hold in honest flow)
    vvid_data = {
        "presented_id": id_resp["presented_id"],
        "voter_unique_id": id_resp["voter_unique_id"],
    }
    if not verify_signature(str(ID_PUBKEY_FILE), vvid_data, id_resp["id_service_signature"]):
        print("Invalid signature from ID server (honest flow)")
        return id_resp, {}

    timestamp = int(time.time() * 1000)
    checkin_body = {
        "client_id_num": int(cfg["Basic"]["client_id"]),
        "timestamp": timestamp,
        "first_name": fn,
        "middle_name": mn,
        "last_name": ln,
        "voter_unique_id": id_resp["voter_unique_id"],
        "verified_id_message": id_resp,
    }

    private_key_path = cfg["Security"]["private_key"]
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
        "client_signature": base64.b64encode(checkin_sig).decode(),
    }

    checkin_resp = timed_lenpref_request(
        checkin_sock, checkin_request, receive_checkin_response, "checkin_service",
        extra={"voter_id": voter_id, "mode": "honest"},
    )

    # Verify check-in signature
    if verify_signature(str(CHECKIN_PUBKEY_FILE), checkin_resp["body"], checkin_resp["checkin_service_signature"]):
        print("Valid checkin response signature (honest flow)")
        ticket = checkin_resp["body"]["ticket"]
        send_ticket_to_trusted(cfg, ticket, int(cfg["Basic"]["client_id"]), voter_id, phase_label="trusted_honest")
    else:
        print("Invalid signature in checkin response (honest flow)")

    return id_resp, checkin_resp


def attack_simple_replay(cfg, voter_sock, checkin_sock, voter):
    """
    Simple replay attack (Section 3.3: Simple Replay Attacks).

    We perform an honest ID + first check-in, then immediately replay the same
    check-in request again within the freshness window.
    """
    voter_id = voter["id"]
    fn, mn, ln = voter["first_name"], voter["middle_name"], voter["last_name"]

    # First honest ID query
    id_req = build_voter_id_request(cfg, fn, mn, ln, voter_id)
    id_resp = timed_lenpref_request(
        voter_sock, id_req, receive_voter_id, "id_service_simple_replay",
        extra={"voter_id": voter_id, "mode": "simple_replay_first"},
    )

    vvid_data = {
        "presented_id": id_resp["presented_id"],
        "voter_unique_id": id_resp["voter_unique_id"],
    }

    if not verify_signature(str(ID_PUBKEY_FILE), vvid_data, id_resp["id_service_signature"]):
        print("Invalid signature from ID server in simple replay (first)")
        return

    timestamp = int(time.time() * 1000)
    checkin_body = {
        "client_id_num": int(cfg["Basic"]["client_id"]),
        "timestamp": timestamp,
        "first_name": fn,
        "middle_name": mn,
        "last_name": ln,
        "voter_unique_id": id_resp["voter_unique_id"],
        "verified_id_message": id_resp,
    }

    private_key_path = cfg["Security"]["private_key"]
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
        "client_signature": base64.b64encode(checkin_sig).decode(),
    }

    # First send: normal behavior
    first_resp = timed_lenpref_request(
        checkin_sock, checkin_request, receive_checkin_response,
        "checkin_service_simple_replay_first",
        extra={"voter_id": voter_id, "mode": "simple_replay_first"},
    )

    print("First check-in response (simple replay):", first_resp.get("body", {}))

    # Immediate replay of the *same* request (including timestamp & signatures)
    second_resp = timed_lenpref_request(
        checkin_sock, checkin_request, receive_checkin_response,
        "checkin_service_simple_replay_second",
        extra={"voter_id": voter_id, "mode": "simple_replay_second"},
    )

    print("Second (replayed) check-in response:", second_resp.get("body", {}))


def attack_stale_replay(cfg, voter_sock, checkin_sock, voter, delay_seconds: float):
    """
    Delayed replay attack (Section 3.3: Completing an Abandoned Check-In / Delayed Replay).

    Same as simple_replay, but we wait long enough that the timestamp should no longer
    be considered fresh by the server, so the second request should be rejected.
    """
    voter_id = voter["id"]
    fn, mn, ln = voter["first_name"], voter["middle_name"], voter["last_name"]

    id_req = build_voter_id_request(cfg, fn, mn, ln, voter_id)
    id_resp = timed_lenpref_request(
        voter_sock, id_req, receive_voter_id, "id_service_stale_replay",
        extra={"voter_id": voter_id, "mode": "stale_replay_first"},
    )

    vvid_data = {
        "presented_id": id_resp["presented_id"],
        "voter_unique_id": id_resp["voter_unique_id"],
    }
    if not verify_signature(str(ID_PUBKEY_FILE), vvid_data, id_resp["id_service_signature"]):
        print("Invalid signature from ID server in stale replay (first)")
        return

    timestamp = int(time.time() * 1000)
    checkin_body = {
        "client_id_num": int(cfg["Basic"]["client_id"]),
        "timestamp": timestamp,
        "first_name": fn,
        "middle_name": mn,
        "last_name": ln,
        "voter_unique_id": id_resp["voter_unique_id"],
        "verified_id_message": id_resp,
    }

    private_key_path = cfg["Security"]["private_key"]
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
        "client_signature": base64.b64encode(checkin_sig).decode(),
    }

    first_resp = timed_lenpref_request(
        checkin_sock, checkin_request, receive_checkin_response,
        "checkin_service_stale_replay_first",
        extra={"voter_id": voter_id, "mode": "stale_replay_first"},
    )
    print("First check-in response (stale replay):", first_resp.get("body", {}))

    # Sleep long enough that the timestamp should become stale relative to the server's
    # pending-check-in timeout window.
    print(f"Sleeping {delay_seconds:.1f}s before replaying stale check-in request...")
    time.sleep(delay_seconds)

    try:
        second_resp = timed_lenpref_request(
            checkin_sock, checkin_request, receive_checkin_response,
            "checkin_service_stale_replay_second",
            extra={"voter_id": voter_id, "mode": "stale_replay_second"},
        )
        print("Second (stale replay) response:", second_resp)
    except Exception as e:
        print("Stale replay appears rejected by server:", e)


def attack_ticket_substitution(cfg, voter_sock, checkin_sock, voter_a, voter_b):
    """
    Ticket substitution attack (Section 3.3: Ticket Substitution).

    We obtain a check-in ticket for voter B, but then send it to the trusted
    sink as if it belonged to voter A (with A's PIN). The check-in server
    should detect a mismatch between the ticket's voter and the provided PIN.
    """
    # Pick B as the "absent" voter whose ticket we will misuse
    voter_b_id = voter_b["id"]
    fn_b, mn_b, ln_b = voter_b["first_name"], voter_b["middle_name"], voter_b["last_name"]

    # Honest ID + check-in for voter B (from the perspective of the servers)
    id_req_b = build_voter_id_request(cfg, fn_b, mn_b, ln_b, voter_b_id)
    id_resp_b = timed_lenpref_request(
        voter_sock, id_req_b, receive_voter_id, "id_service_ticket_substitution",
        extra={"voter_id": voter_b_id, "mode": "ticket_substitution_id"},
    )

    vvid_data_b = {
        "presented_id": id_resp_b["presented_id"],
        "voter_unique_id": id_resp_b["voter_unique_id"],
    }
    if not verify_signature(str(ID_PUBKEY_FILE), vvid_data_b, id_resp_b["id_service_signature"]):
        print("Invalid signature from ID server in ticket substitution")
        return

    timestamp_b = int(time.time() * 1000)
    checkin_body_b = {
        "client_id_num": int(cfg["Basic"]["client_id"]),
        "timestamp": timestamp_b,
        "first_name": fn_b,
        "middle_name": mn_b,
        "last_name": ln_b,
        "voter_unique_id": id_resp_b["voter_unique_id"],
        "verified_id_message": id_resp_b,
    }

    private_key_path = cfg["Security"]["private_key"]
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )
    checkin_sig_b = private_key.sign(
        json.dumps(checkin_body_b, sort_keys=True, separators=(",", ":")).encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    checkin_request_b = {
        "body": checkin_body_b,
        "client_signature": base64.b64encode(checkin_sig_b).decode(),
    }

    checkin_resp_b = timed_lenpref_request(
        checkin_sock, checkin_request_b, receive_checkin_response,
        "checkin_service_ticket_substitution",
        extra={"voter_id": voter_b_id, "mode": "ticket_substitution_checkin"},
    )
    print("Check-in response for voter B:", checkin_resp_b.get("body", {}))

    if not verify_signature(str(CHECKIN_PUBKEY_FILE), checkin_resp_b["body"], checkin_resp_b["checkin_service_signature"]):
        print("Invalid check-in response signature for voter B in ticket substitution")
        return

    ticket_b = checkin_resp_b["body"]["ticket"]

    # Now misuse ticket_b by pairing it with voter A's PIN at the trusted sink.
    voter_a_id = voter_a["id"]
    print(f"Sending ticket for voter B (UID={voter_b_id}) using voter A's PIN (UID={voter_a_id})")
    send_ticket_to_trusted(
        cfg,
        ticket_b,
        int(cfg["Basic"]["client_id"]),
        voter_a_id,
        phase_label="trusted_ticket_substitution",
    )


def pick_two_distinct_voters(voters: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    assert len(voters) >= 2, "Need at least two voters in CSV for ticket-substitution tests"
    a = random.choice(voters)
    b = random.choice(voters)
    while b["id"] == a["id"]:
        b = random.choice(voters)
    return a, b


def main():
    parser = argparse.ArgumentParser(prog="client")
    parser.add_argument("cfg_file", type=Path)
    parser.add_argument(
        "--mode",
        choices=["honest", "simple-replay", "stale-replay", "ticket-substitution"],
        default="honest",
        help="Client behavior to emulate (default: honest).",
    )
    parser.add_argument(
        "--stale-delay",
        type=float,
        default=120.0,
        help="Seconds to wait before replay in stale-replay mode (default: 120s).",
    )
    args = parser.parse_args()

    cfg = load_config(str(args.cfg_file))
    voters_csv = Path(cfg["Basic"]["voters_csv"])

    voters = load_voters_csv(voters_csv)
    if not voters:
        print("No voters loaded from CSV")
        sys.exit(1)

    voter_sock, checkin_sock = create_tls_sockets(cfg)

    if args.mode == "honest":
        v = random.choice(voters)
        honest_flow(cfg, voter_sock, checkin_sock, v)

    elif args.mode == "simple-replay":
        v = random.choice(voters)
        attack_simple_replay(cfg, voter_sock, checkin_sock, v)

    elif args.mode == "stale-replay":
        v = random.choice(voters)
        attack_stale_replay(cfg, voter_sock, checkin_sock, v, delay_seconds=args.stale_delay)

    elif args.mode == "ticket-substitution":
        voter_a, voter_b = pick_two_distinct_voters(voters)
        attack_ticket_substitution(cfg, voter_sock, checkin_sock, voter_a, voter_b)

    voter_sock.close()
    checkin_sock.close()


if __name__ == "__main__":
    main()
