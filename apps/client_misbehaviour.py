import socket, csv, argparse, os, time, random, threading
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

# Contention test beds record here, in the 7-column schema that stress_test.py's
# merge expects (ts,service,run_idx,phase,latency_ms,ok,meta_json), to the file
# it docker-cp's out (--untrusted-metrics-path, default basename untrusted.csv).
# This is what makes the latencies survive into logs/metrics/untrusted_latencies.csv;
# the legacy LAT_FILE above (4-col, wrong basename) was never collected by the merge.
# Absolute path == stress_test.py's DEFAULT --untrusted-metrics-path, so the existing
# docker-cp + merge collects it with NO extra flag. (Verified writable in the image.)
CONTENTION_LAT_FILE = Path("/app/metrics/untrusted.csv")
CONTENTION_HEADER = ["ts", "service", "run_idx", "phase", "latency_ms", "ok", "meta_json"]
SERVICE_NAME = ""          # set in main() from cfg (e.g. "untrusted-client-0")
_RUN_SEQ = 0               # per-process monotonic request counter


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

    # Per-process/thread temp name so concurrent writers don't clobber each other's rename
    tmp = out_path.with_suffix(out_path.suffix + f".{os.getpid()}.{threading.get_ident()}.tmp")
    with open(tmp, "wb") as f:
        f.write(pem)
    tmp.replace(out_path)


def create_tls_context(certfile: str, keyfile: str, cafile: str) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


# Bound connect + handshake + data-recv so a saturated single-threaded server
# can't block a measurement loop forever (a non-responding peer raises and the
# caller records ok=False instead of hanging).
TLS_TIMEOUT_S = 10.0


def tls_handshake(host: str, port: int, context: ssl.SSLContext, label: str,
                  timeout: float = TLS_TIMEOUT_S) -> ssl.SSLSocket:
    sock = socket.create_connection((host, port), timeout=timeout)
    ssock = context.wrap_socket(sock, server_hostname=host)
    ssock.settimeout(timeout)  # bound subsequent recv/send
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


def create_checkin_socket(cfg):
    """Open a fresh mTLS connection to the check-in service only (no ID socket).
    Used to replay a request on a new connection, since the server closes the
    socket after each single-use check-in response."""
    context = create_tls_context(
        cfg["Security"]["local_cert"],
        cfg["Security"]["private_key"],
        cfg["Security"]["ca_cert"],
    )
    checkin_socket = tls_handshake(
        cfg["Basic"]["checkin_service_host"],
        int(cfg["Basic"]["checkin_service_port"]),
        context,
        "CheckinServer",
    )
    extract_and_store_peer_pubkey(checkin_socket, CHECKIN_PUBKEY_FILE)
    return checkin_socket


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


def submit_ticket_to_trusted(cfg, ticket, voter_id, pin, phase_label, ack_timeout=15.0):
    """Hand a (ticket, pin) to the trusted device (Phase 2) and RETURN its ack
    ({"received":..., "approved":...}). Unlike send_ticket_to_trusted, the PIN is
    explicit (so a misbehaviour test can submit a deliberately wrong one) and the
    ack is returned so the caller can assert whether a voting-access token was
    granted. ack_timeout must exceed the trusted device's own ~10s check-in timeout
    so a wrong-PIN denial (the check-in service sends no response) is still seen."""
    host = cfg["Basic"]["ticket_sink_host"]
    port = int(cfg["Basic"]["ticket_sink_port"])
    payload = {
        "client_id": int(cfg["Basic"]["client_id"]),
        "pin": int(pin),
        "ticket": ticket,
        "timestamp": int(time.time() * 1000),
    }
    wire = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ack = None
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=10) as s:
            send_len_prefixed_bytes(s, wire)
            s.settimeout(ack_timeout)
            ack_len = b""
            while not ack_len.endswith(b"\n"):
                chunk = s.recv(1)
                if not chunk:
                    break
                ack_len += chunk
            if ack_len.strip():
                n = int(ack_len.strip())
                body = b""
                while len(body) < n:
                    chunk = s.recv(n - len(body))
                    if not chunk:
                        break
                    body += chunk
                ack = json.loads(body.decode())
    except Exception as exc:
        ack = {"received": False, "error": f"no ack: {exc}"}
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    _csv_append(
        LAT_FILE,
        [phase_label, f"{elapsed_ms:.3f}", bool(ack and ack.get("approved")), json.dumps({"voter_id": voter_id})],
        header=["phase", "latency_ms", "ok", "meta_json"],
    )
    return ack


_csv_lock = threading.Lock()


def _csv_append(path: Path, row: List[Any], header: List[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with _csv_lock:
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
    Ticket substitution attack (§3.3) — colluding-vs-oblivious PIN refinement.

    An attacker obtains a valid Phase-1 check-in ticket for voter B (e.g. B is
    absent, or the attacker checked B in) and tries to redeem it at the trusted
    device so that a DIFFERENT person votes. The check-in server derives the voter
    purely from the TICKET (handle_trusted_client: voter_id = client_tickets_map[
    ticket].first, checkin_service.cpp:256) and checks the submitted PIN against
    THAT voter's real PIN (:269). So the only thing protecting B's ticket is B's
    own election PIN — a secret that never travels the untrusted path.

    This test makes that boundary explicit by driving BOTH sub-cases on the same
    ticket, in order (the wrong-PIN path returns at :291 BEFORE consuming the
    ticket/timer, so the ticket survives for the second attempt):

      1. OBLIVIOUS impostor — voter A holds B's ticket but does NOT know B's PIN,
         so A enters their own PIN (a PIN that is not B's). This MUST be denied;
         it is the real security boundary for substitution.
      2. COLLUDING voter — B hands over their real PIN, so the attacker submits
         B's correct PIN. This is EXPECTED to succeed: the system cannot stop a
         voter from giving away their own secret (equivalent to B voting by proxy).
         It also serves as a positive control proving the ticket was genuinely
         redeemable, so the oblivious denial is attributable to the PIN, not a
         dead ticket.

    PASS (rc=0)  -> oblivious attempt DENIED *and* colluding attempt APPROVED:
                    substitution is blocked unless the attacker also holds the
                    voter's PIN (two-phase binding holds; colluding is out of scope).
    FAIL (rc=1)  -> oblivious attempt APPROVED: B's ticket was redeemed WITHOUT
                    B's PIN — substitution succeeds, second factor not bound to the
                    ticket's voter (real break).
    INCONCLUSIVE (rc=2) -> no PIN CSV configured, or the colluding (correct-PIN)
                    control was itself denied (ticket not redeemable, e.g. expired),
                    so the oblivious denial cannot be attributed to the PIN binding.
    """
    voter_a_id = voter_a["id"]
    voter_b_id = voter_b["id"]

    pin_csv = cfg["Basic"].get("pin_csv", "").strip()
    if not pin_csv:
        print("INCONCLUSIVE: no pin_csv configured; cannot exercise the PIN binding")
        sys.exit(2)
    try:
        b_pin = get_pin_for_id(pin_csv, voter_b_id)
        a_pin = get_pin_for_id(pin_csv, voter_a_id)
    except Exception as exc:
        print(f"INCONCLUSIVE: could not load PINs from {pin_csv} ({exc})")
        sys.exit(2)

    # ---- Capture a genuine Phase-1 ticket for voter B (honest check-in, not
    #      forwarded to the trusted device — the attacker holds the ticket).
    approved_b, ticket_b, _ = perform_honest_checkin(
        cfg, voter_sock, checkin_sock, voter_b, "ticket_sub_phase1")
    print(f"Captured a Phase-1 ticket for voter B (UID={voter_b_id}): "
          f"approved={approved_b}, ticket={'<issued>' if ticket_b else '<none>'}")
    if not approved_b or not ticket_b:
        print("INCONCLUSIVE: could not obtain a ticket for voter B "
              "(B may already be checked in)")
        sys.exit(2)

    # ---- (1) OBLIVIOUS: voter A redeems B's ticket with a PIN that is not B's.
    #      A enters their own PIN; if it happens to equal B's, bump it so the
    #      attempt is deterministically a non-B PIN (A genuinely doesn't know B's).
    oblivious_pin = a_pin if a_pin != b_pin else (b_pin + 1)
    print(f"(1) OBLIVIOUS: submitting voter B's ticket with voter A's PIN (UID={voter_a_id}, "
          f"a PIN that is not B's) — must be denied")
    ack_oblivious = submit_ticket_to_trusted(
        cfg, ticket_b, voter_b_id, oblivious_pin, "trusted_ticket_sub_oblivious")
    print(f"    trusted-device ack: {ack_oblivious}")
    oblivious_granted = bool(ack_oblivious and ack_oblivious.get("approved"))
    if oblivious_granted:
        print(f"FAIL: voter B's ticket (UID={voter_b_id}) was redeemed WITHOUT B's PIN — "
              f"ticket substitution succeeds; the second factor is not bound to the "
              f"ticket's voter (real break).")
        sys.exit(1)

    # ---- (2) COLLUDING: B hands over their real PIN. Expected to succeed — this is
    #      the positive control and documents the inherent limit (a voter sharing
    #      their own secret is equivalent to that voter voting).
    print(f"(2) COLLUDING: submitting voter B's ticket with B's REAL PIN — expected to "
          f"succeed (a colluding voter sharing their PIN is out of scope)")
    ack_colluding = submit_ticket_to_trusted(
        cfg, ticket_b, voter_b_id, b_pin, "trusted_ticket_sub_colluding")
    print(f"    trusted-device ack: {ack_colluding}")
    colluding_granted = bool(ack_colluding and ack_colluding.get("approved"))
    if not colluding_granted:
        print("INCONCLUSIVE: the colluding (correct-PIN) control was denied, so B's ticket "
              "was not redeemable at all (e.g. expired/consumed) — the oblivious denial "
              "cannot be attributed to the PIN binding.")
        sys.exit(2)

    print(f"PASS: voter B's ticket was DENIED to an oblivious impostor (no B PIN) but "
          f"redeemed only with B's own PIN — ticket substitution is blocked unless the "
          f"attacker also holds the voter's secret (two-phase PIN binding holds).")
    sys.exit(0)


def attack_cross_identity(cfg, voter_sock, checkin_sock, voter_victim, voter_real):
    """
    Cross-identity forwarding (§3.3 / UID cross-check).

    Obtain a *valid* signed VerifiedVoterID for voter_real (B) from the ID
    server, then submit a check-in whose body claims voter_victim's (A's) UID
    and name but embeds B's signed verified_id_message.

    The check-in server verifies (a) the client signature over the whole body
    (valid — we own the key) and (b) the ID-service signature over B's
    {presented_id, voter_unique_id=B} (valid), but it transitions the
    voter-status table using body.voter_unique_id (= A). If it never compares
    body.voter_unique_id against verified_id_message.voter_unique_id, it checks
    in A on the strength of B's ID proof.

    PASS (rc=0)  -> server REJECTS  (UID cross-check present / fires).
    FAIL (rc=1)  -> server ACCEPTS  (approved=True): A checked in with B's ID
                    verification — cross-check missing. Real finding.
    INCONCLUSIVE (rc=2) -> error / no parseable response.
    """
    a_id = voter_victim["id"]
    b_id = voter_real["id"]
    fn_a, mn_a, ln_a = voter_victim["first_name"], voter_victim["middle_name"], voter_victim["last_name"]
    fn_b, mn_b, ln_b = voter_real["first_name"], voter_real["middle_name"], voter_real["last_name"]

    # ---- Honest ID query for the REAL voter B (yields a valid signed VVID, UID=B)
    id_req_b = build_voter_id_request(cfg, fn_b, mn_b, ln_b, b_id)
    id_resp_b = timed_lenpref_request(
        voter_sock, id_req_b, receive_voter_id, "id_service_cross_identity",
        extra={"voter_id": b_id, "mode": "cross_identity_id"},
    )

    vvid_data_b = {
        "presented_id": id_resp_b["presented_id"],
        "voter_unique_id": id_resp_b["voter_unique_id"],
    }
    if not verify_signature(str(ID_PUBKEY_FILE), vvid_data_b, id_resp_b["id_service_signature"]):
        print("Invalid signature from ID server in cross-identity (real voter B)")
        sys.exit(2)

    # ---- Craft the mismatch: claim victim A's UID/name, attach B's signed VVID
    checkin_body = {
        "client_id_num": int(cfg["Basic"]["client_id"]),
        "timestamp": int(time.time() * 1000),
        "first_name": fn_a,
        "middle_name": mn_a,
        "last_name": ln_a,
        "voter_unique_id": a_id,              # claimed victim A (status-table key)
        "verified_id_message": id_resp_b,     # B's signed ID proof (UID=B)
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

    print(f"Cross-identity: claiming victim A (UID={a_id}) backed by real B's ID proof (UID={b_id})")

    try:
        resp = timed_lenpref_request(
            checkin_sock, checkin_request, receive_checkin_response,
            "checkin_cross_identity",
            extra={"victim_uid": a_id, "real_uid": b_id, "mode": "cross_identity"},
        )
    except Exception as exc:
        print(f"INCONCLUSIVE: no parseable check-in response ({exc})")
        sys.exit(2)

    approved = bool(resp.get("body", {}).get("approved"))
    print(f"Check-in response: approved={approved}, body={resp.get('body', {})}")

    if approved:
        print(f"FAIL: server checked in victim A (UID={a_id}) using voter B's (UID={b_id}) "
              f"ID verification — missing UID cross-check (real finding)")
        sys.exit(1)
    print("PASS: server rejected the cross-identity request (UID cross-check holds)")
    sys.exit(0)


def attack_tampered_body(cfg, voter_sock, checkin_sock, voter_a, voter_b):
    """
    Tampered signed body (§3.3 / client-signature integrity).

    Build an honest, correctly-signed check-in request for voter A, then mutate
    the body (swap voter_unique_id + names A -> B) WITHOUT re-signing. The
    attached client_signature still covers the original A-body, not what is on
    the wire.

    The check-in server recomputes the signature over the *received* body in
    validate_client_request (checkin_service.cpp:636-648); verification must
    fail and the request be rejected.

    PASS (rc=0)  -> server REJECTS  (signature check catches the tamper).
    FAIL (rc=1)  -> server ACCEPTS  (approved=True): signature not enforced over
                    the body — serious integrity break.
    INCONCLUSIVE (rc=2) -> error / no parseable response.

    NOTE: the server's signature-failure path currently logs at debug and does
    NOT call FaultTracker::reportFault, so no fault is filed for this attack. The
    PDF expects a fault report here — separate hardening gap, not a test failure.
    """
    a_id = voter_a["id"]
    b_id = voter_b["id"]
    fn_a, mn_a, ln_a = voter_a["first_name"], voter_a["middle_name"], voter_a["last_name"]
    fn_b, mn_b, ln_b = voter_b["first_name"], voter_b["middle_name"], voter_b["last_name"]

    # ---- Honest ID query for voter A
    id_req = build_voter_id_request(cfg, fn_a, mn_a, ln_a, a_id)
    id_resp = timed_lenpref_request(
        voter_sock, id_req, receive_voter_id, "id_service_tampered_body",
        extra={"voter_id": a_id, "mode": "tampered_body_id"},
    )

    vvid_data = {
        "presented_id": id_resp["presented_id"],
        "voter_unique_id": id_resp["voter_unique_id"],
    }
    if not verify_signature(str(ID_PUBKEY_FILE), vvid_data, id_resp["id_service_signature"]):
        print("Invalid signature from ID server in tampered-body (voter A)")
        sys.exit(2)

    # ---- Honest, correctly-signed check-in body for voter A
    checkin_body = {
        "client_id_num": int(cfg["Basic"]["client_id"]),
        "timestamp": int(time.time() * 1000),
        "first_name": fn_a,
        "middle_name": mn_a,
        "last_name": ln_a,
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

    # ---- TAMPER: rewrite the body to voter B *after* signing (signature unchanged)
    checkin_body["voter_unique_id"] = b_id
    checkin_body["first_name"] = fn_b
    checkin_body["middle_name"] = mn_b
    checkin_body["last_name"] = ln_b

    checkin_request = {
        "body": checkin_body,                                        # now describes B
        "client_signature": base64.b64encode(checkin_sig).decode(),  # still signs A
    }

    print(f"Tampered body: signed for voter A (UID={a_id}) but rewrote body to voter B (UID={b_id}) without re-signing")

    try:
        resp = timed_lenpref_request(
            checkin_sock, checkin_request, receive_checkin_response,
            "checkin_tampered_body",
            extra={"signed_uid": a_id, "wire_uid": b_id, "mode": "tampered_body"},
        )
    except Exception as exc:
        print(f"INCONCLUSIVE: no parseable check-in response ({exc})")
        sys.exit(2)

    approved = bool(resp.get("body", {}).get("approved"))
    print(f"Check-in response: approved={approved}, body={resp.get('body', {})}")

    if approved:
        print(f"FAIL: server accepted a body whose signature does not cover it "
              f"(signed UID={a_id}, wire UID={b_id}) — signature integrity not enforced")
        sys.exit(1)
    print("PASS: server rejected the tampered body (client-signature integrity holds)")
    sys.exit(0)


RACE_ALT_CLIENT_ID   = 2
RACE_ALT_PRIVATE_KEY = "private_key_alt.pem"
RACE_ALT_LOCAL_CERT  = "certificate_alt.pem"


def _identity_cfg(cfg, client_id, private_key, local_cert):
    """Shallow clone of cfg with the identity-bearing fields overridden so a
    thread can act as a distinct client (own client_id, signing key, and cert)."""
    clone = configparser.ConfigParser()
    clone.read_dict({s: dict(cfg[s]) for s in cfg.sections()})
    clone["Basic"]["client_id"] = str(client_id)
    clone["Security"]["private_key"] = private_key
    clone["Security"]["local_cert"] = local_cert
    return clone


def _load_alt_private_key(cfg, alt_key_name):
    """Load another client's private key (e.g. private_key_alt.pem) for the
    spoofing tests. Resolve the name relative to cwd, the configured key's
    directory, or this file's directory — wherever the alt key actually lives."""
    candidates = [
        Path(alt_key_name),
        Path(cfg["Security"]["private_key"]).parent / alt_key_name,
        Path(__file__).parent / alt_key_name,
    ]
    for c in candidates:
        if c.exists():
            with open(c, "rb") as f:
                return serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
    raise FileNotFoundError(
        f"alt private key not found; tried {[str(c) for c in candidates]}"
    )


def attack_spoofed_client_id(cfg, voter_sock, checkin_sock, voter):
    """
    Spoofed client_id_num (§3.3 / client-identity binding; guard at checkin_service.cpp:531).

    The TLS session authenticates this process as its real client (cert-derived
    client_id, e.g. 0). We then submit a check-in whose body claims a DIFFERENT
    client_id_num (the alt client, e.g. 2) and sign it with that other client's
    private key (private_key_alt.pem). The ID step is honest, and the voter
    UID/name match the signed VVID, so the cross-identity guard is NOT what trips —
    this isolates the client-identity binding.

    The server selects the signature verifier by body.client_id_num (the claimed
    id), so the alt-key signature verifies. The only place that compares the
    cert-derived identity against the claimed client_id_num is the guard at
    checkin_service.cpp:531, which currently only logs a warning and does not
    reject. If that guard does not enforce, the server checks the voter in and
    attributes it to a client that did NOT open the TLS connection
    (identity spoofing / audit repudiation).

    PASS (rc=0)  -> server REJECTS (cert-vs-claimed identity check enforced).
    FAIL (rc=1)  -> server ACCEPTS (approved=True): check-in attributed to a
                    spoofed client_id_num though a different client authenticated
                    the TLS session — guard non-enforcing. Real finding.
    INCONCLUSIVE (rc=2) -> error / no parseable response.
    """
    voter_id = voter["id"]
    fn, mn, ln = voter["first_name"], voter["middle_name"], voter["last_name"]

    real_client_id = int(cfg["Basic"]["client_id"])
    spoof_client_id = RACE_ALT_CLIENT_ID                       # claim to be this client...
    spoof_signing_key = _load_alt_private_key(cfg, RACE_ALT_PRIVATE_KEY)  # ...and sign with its key

    # ---- Honest ID query (signed as our REAL client over the established TLS session)
    id_req = build_voter_id_request(cfg, fn, mn, ln, voter_id)
    id_resp = timed_lenpref_request(
        voter_sock, id_req, receive_voter_id, "id_service_spoofed_client",
        extra={"voter_id": voter_id, "mode": "spoofed_client_id_id"},
    )

    vvid_data = {
        "presented_id": id_resp["presented_id"],
        "voter_unique_id": id_resp["voter_unique_id"],
    }
    if not verify_signature(str(ID_PUBKEY_FILE), vvid_data, id_resp["id_service_signature"]):
        print("Invalid signature from ID server in spoofed-client-id")
        sys.exit(2)

    # ---- Check-in body claims the SPOOF client id; UID/name honest so the
    #      cross-identity guard is not what rejects (isolates the identity guard).
    checkin_body = {
        "client_id_num": spoof_client_id,
        "timestamp": int(time.time() * 1000),
        "first_name": fn,
        "middle_name": mn,
        "last_name": ln,
        "voter_unique_id": id_resp["voter_unique_id"],
        "verified_id_message": id_resp,
    }

    # Sign with the SPOOF client's key so the server's verifier (keyed on the
    # claimed client_id_num) accepts the signature.
    checkin_sig = spoof_signing_key.sign(
        json.dumps(checkin_body, sort_keys=True, separators=(",", ":")).encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    checkin_request = {
        "body": checkin_body,
        "client_signature": base64.b64encode(checkin_sig).decode(),
    }

    print(f"Spoofed client_id: TLS-authenticated as client {real_client_id}, "
          f"but body claims client {spoof_client_id} and is signed with that client's key")

    try:
        resp = timed_lenpref_request(
            checkin_sock, checkin_request, receive_checkin_response,
            "checkin_spoofed_client",
            extra={"real_client": real_client_id, "claimed_client": spoof_client_id,
                   "mode": "spoofed_client_id"},
        )
    except Exception as exc:
        print(f"INCONCLUSIVE: no parseable check-in response ({exc})")
        sys.exit(2)

    approved = bool(resp.get("body", {}).get("approved"))
    print(f"Check-in response: approved={approved}, body={resp.get('body', {})}")

    if approved:
        print(f"FAIL: server accepted a check-in claiming client {spoof_client_id} over a "
              f"TLS session authenticated as client {real_client_id} — identity guard at "
              f"checkin_service.cpp:531 is non-enforcing (real finding)")
        sys.exit(1)
    print("PASS: server rejected the spoofed client_id_num "
          "(cert-vs-claimed identity binding enforced)")
    sys.exit(0)


def attack_delayed_replay(cfg, voter_sock, checkin_sock, voter, delay_seconds):
    """
    Delayed replay via stored ID images (§3.3).

    Models an attacker who captures a voter's raw ID-card bytes during a
    legitimate presentation, stores them, and reuses them LATER to mint a
    brand-new signed VerifiedVoterID from the ID server. The ID server only
    bounds the *request* timestamp (request_freshness_interval = 5000 ms); it
    does NOT bind issuance to a live presentation, a nonce, or single-use, so the
    same captured image yields a fresh VVID at any later time. That VVID then
    drives a full check-in.

    Distinct from stale-replay: stale-replay re-sends the SAME signed artifact and
    is rejected by the freshness check. Here we RE-MINT a fresh VVID from the
    stored bytes AFTER the freshness window has elapsed, so the delay does not
    stop the attack — that contrast is the whole point.

    Per the paper (pollboo_paper.pdf §3.1, §5), the Voter ID Service is INTENTIONALLY
    stateless (privacy), so re-minting a VVID from valid ID data is by design and a
    Phase-1 check-in ticket is EXPECTED — it is NOT the security boundary. The
    mitigation is the two-phase model: final confirmation requires the voter's
    election PIN at the TRUSTED device, a secret never on the untrusted path. So
    this test drives Phase 2 with the stored-image ticket but a WRONG PIN (modeling
    an attacker who has the captured image but not the secret) and asserts that no
    voting-access token is granted.

    PASS (rc=0)  -> Phase-2 trusted device DENIES the voting token without the PIN
                    (two-phase mitigation holds), OR the replay never even yields a
                    Phase-1 ticket.
    FAIL (rc=1)  -> trusted device grants a voting-access token from a stored image
                    WITHOUT the correct PIN — second-factor not enforced (real break).
    INCONCLUSIVE (rc=2) -> error / no parseable response in Phase 1.
    """
    voter_id = voter["id"]
    fn, mn, ln = voter["first_name"], voter["middle_name"], voter["last_name"]

    # ---- Phase 1 (CAPTURE): a legitimate presentation happens and we observe
    #      the voter's ID image. We query the ID server but do NOT check the voter
    #      in, so the voter stays ELIGIBLE for the later replay.
    id_req_capture = build_voter_id_request(cfg, fn, mn, ln, voter_id)
    captured_image = id_req_capture["body"]["voter_id_data"]   # the stored ID-card bytes (base64)
    vvid_capture = timed_lenpref_request(
        voter_sock, id_req_capture, receive_voter_id, "id_service_delayed_replay_capture",
        extra={"voter_id": voter_id, "mode": "delayed_replay_capture"},
    )
    if not verify_signature(str(ID_PUBKEY_FILE),
                            {"presented_id": vvid_capture["presented_id"],
                             "voter_unique_id": vvid_capture["voter_unique_id"]},
                            vvid_capture["id_service_signature"]):
        print("Invalid signature from ID server during capture phase")
        sys.exit(2)
    print(f"Captured ID image for UID {voter_id} (VVID issued at "
          f"{vvid_capture['presented_id']['body']['timestamp']})")

    # ---- DELAY: simulate time passing. Must exceed the 5000 ms freshness window
    #      so this is genuinely a *delayed* reuse, not a same-window resend.
    print(f"Storing the ID image and waiting {delay_seconds:.1f}s "
          f"(freshness window is 5s) before reusing it...")
    time.sleep(delay_seconds)

    # ---- Phase 2 (REPLAY): the attacker reconnects LATER and, using ONLY the
    #      stored image bytes, builds a NEW ID request with a FRESH timestamp +
    #      signature to re-query the ID server. A fresh connection is required: the
    #      ID server handles one request per connection (start_payload_read does not
    #      re-arm a read), and reconnecting also faithfully models a later session.
    replay_voter_sock, replay_checkin_sock = create_tls_sockets(cfg)

    id_req_replay = build_voter_id_request(cfg, fn, mn, ln, voter_id)
    # Prove it is the SAME captured image, just a new request envelope.
    assert id_req_replay["body"]["voter_id_data"] == captured_image, \
        "replay must reuse the identical stored ID image bytes"

    try:
        vvid_replay = timed_lenpref_request(
            replay_voter_sock, id_req_replay, receive_voter_id, "id_service_delayed_replay",
            extra={"voter_id": voter_id, "mode": "delayed_replay_remint"},
        )
    except Exception as exc:
        print(f"INCONCLUSIVE: ID server did not return a VVID on replay ({exc})")
        sys.exit(2)

    if not vvid_replay or "id_service_signature" not in vvid_replay:
        print("PASS: ID server refused to re-mint a VVID from the stored image (replay protected)")
        sys.exit(0)
    if not verify_signature(str(ID_PUBKEY_FILE),
                            {"presented_id": vvid_replay["presented_id"],
                             "voter_unique_id": vvid_replay["voter_unique_id"]},
                            vvid_replay["id_service_signature"]):
        print("PASS: re-minted VVID did not carry a valid ID-server signature (replay refused)")
        sys.exit(0)
    print(f"ID server RE-MINTED a fresh VVID from the stored image after {delay_seconds:.1f}s "
          f"(new issuance timestamp {vvid_replay['presented_id']['body']['timestamp']})")

    # ---- Complete a full check-in on the freshly re-minted VVID
    checkin_body = {
        "client_id_num": int(cfg["Basic"]["client_id"]),
        "timestamp": int(time.time() * 1000),
        "first_name": fn,
        "middle_name": mn,
        "last_name": ln,
        "voter_unique_id": vvid_replay["voter_unique_id"],
        "verified_id_message": vvid_replay,
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

    try:
        resp = timed_lenpref_request(
            replay_checkin_sock, checkin_request, receive_checkin_response,
            "checkin_delayed_replay",
            extra={"voter_id": voter_id, "delay_s": delay_seconds, "mode": "delayed_replay"},
        )
    except Exception as exc:
        print(f"INCONCLUSIVE: no parseable check-in response ({exc})")
        sys.exit(2)

    approved = bool(resp.get("body", {}).get("approved"))
    ticket = resp.get("body", {}).get("ticket", "")
    print(f"Phase 1 (check-in from re-minted VVID): approved={approved}, "
          f"ticket={'<issued>' if ticket else '<none>'}")

    if not approved or not ticket:
        # The stateless ID service is expected to re-mint, so Phase 1 normally issues
        # a ticket. If it didn't, the replay was already stopped before Phase 2.
        print("PASS: replayed image did not yield a Phase-1 ticket (stopped before Phase 2)")
        sys.exit(0)

    # ---- Phase 2: the attacker holds the stored image + its Phase-1 ticket but NOT
    #      the voter's election PIN (never on the untrusted path). Attempt final
    #      confirmation at the trusted device with a deliberately WRONG PIN.
    real_pin = None
    pin_csv = cfg["Basic"].get("pin_csv", "").strip()
    if pin_csv:
        try:
            real_pin = get_pin_for_id(pin_csv, voter_id)
        except Exception:
            real_pin = None
    # A real attacker simply does not know the PIN; real_pin+1 guarantees a wrong
    # guess so the wrong-PIN path is exercised deterministically.
    wrong_pin = (int(real_pin) + 1) if real_pin is not None else 999999
    print(f"Phase 2: submitting the replayed-image ticket to the trusted device with a WRONG PIN")

    ack = submit_ticket_to_trusted(cfg, ticket, voter_id, wrong_pin, "trusted_delayed_replay")
    print(f"Trusted-device ack: {ack}")

    granted = bool(ack and ack.get("approved"))
    if granted:
        print(f"FAIL: trusted device issued a voting-access token for UID {voter_id} from a "
              f"stored ID image WITHOUT the correct PIN — two-phase second factor not enforced "
              f"(real break)")
        sys.exit(1)
    print(f"PASS: the stored ID image got a Phase-1 ticket (expected — the ID service is stateless "
          f"by design), but the trusted device DENIED the voting-access token without the voter's "
          f"PIN — the two-phase mitigation holds")
    sys.exit(0)


def perform_honest_checkin(cfg, voter_sock, checkin_sock, voter, label):
    """
    Run ID-query -> check-in for `voter` over the given sockets and return
    (approved, ticket, checkin_resp). Mirrors honest_flow's Phase 1 but does NOT
    forward the ticket to the trusted device, so callers decide whether (and how)
    to drive Phase 2.
    """
    voter_id = voter["id"]
    fn, mn, ln = voter["first_name"], voter["middle_name"], voter["last_name"]

    id_req = build_voter_id_request(cfg, fn, mn, ln, voter_id)
    id_resp = timed_lenpref_request(
        voter_sock, id_req, receive_voter_id, f"id_service_{label}",
        extra={"voter_id": voter_id, "mode": label},
    )
    if not verify_signature(str(ID_PUBKEY_FILE),
                            {"presented_id": id_resp["presented_id"],
                             "voter_unique_id": id_resp["voter_unique_id"]},
                            id_resp["id_service_signature"]):
        print(f"Invalid signature from ID server ({label})")
        return False, "", {}

    checkin_body = {
        "client_id_num": int(cfg["Basic"]["client_id"]),
        "timestamp": int(time.time() * 1000),
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
    resp = timed_lenpref_request(
        checkin_sock, checkin_request, receive_checkin_response,
        f"checkin_{label}",
        extra={"voter_id": voter_id, "mode": label},
    )
    approved = bool(resp.get("body", {}).get("approved"))
    ticket = resp.get("body", {}).get("ticket", "")
    return approved, ticket, resp


def attack_withhold_token(cfg, voter_sock, checkin_sock, voter, withhold_wait):
    """
    Withholding the access token (§3.3).

    A malicious or faulty untrusted client performs a legitimate Phase-1 check-in
    (voter ELIGIBLE -> PENDING, single-use ticket issued) but then NEVER forwards
    the ticket to the trusted device. Per the paper (§4.1), the pending ticket is
    meant to be short-lived: if Phase 2 is not completed, the timeout must revert
    the voter's status back to "not checked in" (ELIGIBLE) so the voter can still
    vote later via a fresh, legitimate check-in.

    This test asserts that self-healing actually happens. It does an honest Phase-1
    check-in, deliberately WITHHOLDS the ticket, waits past the pending timer
    (Config TIMEOUT_INTERVAL minutes on the check-in server), and then attempts a
    brand-new legitimate check-in for the SAME voter on fresh connections.

    PASS (rc=0)  -> the later legitimate check-in is APPROVED: the timeout reverted
                    PENDING -> ELIGIBLE, so the withheld ticket did not strand the voter.
    FAIL (rc=1)  -> the later legitimate check-in is REJECTED: the voter is stuck in
                    PENDING because handle_verification_timeout only erases the timer
                    and never reverts voter_status_table -> a withheld ticket is a
                    permanent, targeted denial-of-service against that voter.
    INCONCLUSIVE (rc=2) -> the initial honest check-in never produced a ticket, or the
                    later check-in errored.
    """
    voter_id = voter["id"]

    # ---- Phase 1: an honest check-in, then WITHHOLD the resulting ticket.
    approved, ticket, _ = perform_honest_checkin(
        cfg, voter_sock, checkin_sock, voter, "withhold_phase1")
    print(f"Phase 1 (honest check-in): approved={approved}, "
          f"ticket={'<issued>' if ticket else '<none>'}")
    if not approved or not ticket:
        print("INCONCLUSIVE: initial honest check-in did not yield a ticket "
              "(voter may already be checked in)")
        sys.exit(2)

    # The misbehaviour: we hold the ticket and never hand it to the trusted device,
    # leaving the voter parked in PENDING.
    print(f"WITHHOLDING the ticket for UID {voter_id} (never forwarded to the trusted "
          f"device). Voter is now PENDING.")
    print(f"Waiting {withhold_wait:.0f}s for the pending timer (Config TIMEOUT_INTERVAL) "
          f"to fire...")
    time.sleep(withhold_wait)

    # ---- After the timeout: the voter legitimately shows up and an HONEST client
    #      attempts a normal check-in. This must succeed if the timeout self-healed.
    retry_voter_sock, retry_checkin_sock = create_tls_sockets(cfg)
    try:
        retry_approved, retry_ticket, _ = perform_honest_checkin(
            cfg, retry_voter_sock, retry_checkin_sock, voter, "withhold_retry")
    except Exception as exc:
        print(f"INCONCLUSIVE: later legitimate check-in errored ({exc})")
        sys.exit(2)
    finally:
        try:
            retry_voter_sock.close()
            retry_checkin_sock.close()
        except Exception:
            pass

    print(f"Later legitimate check-in for UID {voter_id}: approved={retry_approved}, "
          f"ticket={'<issued>' if retry_ticket else '<none>'}")

    if retry_approved and retry_ticket:
        print(f"PASS: after the withheld ticket timed out, UID {voter_id} reverted to "
              f"ELIGIBLE and a legitimate check-in succeeded — the pending timeout "
              f"self-heals as the paper (§4.1) requires.")
        sys.exit(0)

    print(f"FAIL: UID {voter_id} is stranded in PENDING after the withheld ticket timed "
          f"out — handle_verification_timeout erased the timer but never reverted the "
          f"status, so a withheld ticket is a PERMANENT denial-of-service against this "
          f"voter (contradicts paper §4.1).")
    sys.exit(1)


def attack_race_condition(cfg, voter):
    """
    Two connections open independently and both race to check in the same voter.
    The server's ELIGIBLE→PENDING transition is atomic, so exactly one should
    receive approved=True. The loser should be rejected and a FaultTracker entry
    should be filed server-side.
    """
    voter_id = voter["id"]
    fn, mn, ln = voter["first_name"], voter["middle_name"], voter["last_name"]
    identities = [
        cfg,  # Thread 0: this client's own identity (Client 0)
        _identity_cfg(cfg, RACE_ALT_CLIENT_ID, RACE_ALT_PRIVATE_KEY, RACE_ALT_LOCAL_CERT),  # Thread 1: Client 2
    ]


    barrier = threading.Barrier(2)
    results: List[Any] = [None, None]
    errors:  List[Any] = [None, None]

    def attempt(idx: int):
        icfg = identities[idx]
        try:
            voter_sock, checkin_sock = create_tls_sockets(icfg)

            id_req = build_voter_id_request(icfg, fn, mn, ln, voter_id)
            id_resp = timed_lenpref_request(
                voter_sock, id_req, receive_voter_id,
                f"id_service_race_{idx}",
                extra={"voter_id": voter_id, "mode": f"race_{idx}"},
            )

            vvid_data = {
                "presented_id": id_resp["presented_id"],
                "voter_unique_id": id_resp["voter_unique_id"],
            }
            if not verify_signature(str(ID_PUBKEY_FILE), vvid_data, id_resp["id_service_signature"]):
                print(f"Thread {idx}: invalid ID server signature")
                voter_sock.close()
                checkin_sock.close()
                return

            checkin_body = {
                "client_id_num": int(icfg["Basic"]["client_id"]),
                "timestamp": int(time.time() * 1000),
                "first_name": fn,
                "middle_name": mn,
                "last_name": ln,
                "voter_unique_id": id_resp["voter_unique_id"],
                "verified_id_message": id_resp,
            }

            private_key_path = icfg["Security"]["private_key"]
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

            barrier.wait()

            resp = timed_lenpref_request(
                checkin_sock, checkin_request, receive_checkin_response,
                f"checkin_race_{idx}",
                extra={"voter_id": voter_id, "mode": f"race_{idx}"},
            )
            results[idx] = resp
            voter_sock.close()
            checkin_sock.close()
        except Exception as exc:
            errors[idx] = exc
            print(f"Thread {idx} error: {exc}")
            barrier.abort()

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    winners = [i for i, r in enumerate(results) if r and r.get("body", {}).get("approved")]
    losers  = [i for i, r in enumerate(results) if r and not r.get("body", {}).get("approved")]

    print(f"\nRace condition: {len(winners)} approved, {len(losers)} rejected")
    for i, r in enumerate(results):
        if r:
            approved = r.get("body", {}).get("approved")
            ticket   = r.get("body", {}).get("ticket", "")
            print(f"  Thread {i}: approved={approved}, ticket={'<present>' if ticket else '<none>'}")
        elif errors[i]:
            print(f"  Thread {i}: exception — {errors[i]}")
        else:
            print(f"  Thread {i}: no response")

    if len(winners) > 1:
        print("FAIL: more than one check-in approved for the same voter")
        sys.exit(1)

    elif len(winners) == 1:
        print("PASS: exactly one approved, one rejected")
        sys.exit(0)

    else:
        print("INCONCLUSIVE: no check-in approved (server error or both connections failed)")
        sys.exit(2)


# =====================================================================
# Contention test beds (latency under cross-traffic)
# ---------------------------------------------------------------------
# Two MEASUREMENT modes (not pass/fail vulnerability probes):
#   * attacker-reaction-under-load : how fast the server reacts to a
#       misbehaving client while it is busy serving honest voters.
#   * honest-latency-under-attack  : the check-in latency a legitimate
#       voter experiences with vs. without a malicious client attacking.
# Both spin up their own background contention with worker threads against
# the shared, single-threaded check-in server and record per-request
# latencies to the same untrusted_latencies.csv under DISTINCT phase
# labels, so stress_test's bundle separates them automatically:
#   attacker_reaction        (test bed 1, the measured aggressor request)
#   checkin_honest_baseline  (test bed 2, honest latency, no attacker)
#   checkin_honest_under_attack (test bed 2, honest latency while attacked)
#   honest_load / aggressor_load (the background cross-traffic itself)
# =====================================================================

def _timed_request(sock, payload, recv_fn, label, extra=None):
    """Like timed_lenpref_request but returns (resp, elapsed_ms) and never
    raises on a dropped/closed socket (returns ({}, ms)) so a measurement
    loop survives the server hanging up under load."""
    start = time.perf_counter()
    ok = False
    resp = {}
    try:
        send_request(sock, payload)
        resp = recv_fn(sock)
        ok = bool(resp)
    except Exception:
        resp = {}
        ok = False
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    global _RUN_SEQ
    _RUN_SEQ += 1
    _csv_append(
        CONTENTION_LAT_FILE,
        [int(time.time() * 1000), SERVICE_NAME, _RUN_SEQ,
         label, f"{elapsed_ms:.3f}", ok, json.dumps(extra or {})],
        header=CONTENTION_HEADER,
    )
    return resp, elapsed_ms


def _sign_checkin_body(cfg, body, *, signing_key=None, corrupt_sig=False):
    """Sign a prebuilt check-in body and return the {body, client_signature}
    request. `signing_key` forges another client's key; `corrupt_sig` flips a
    byte so the server's signature check fails."""
    if signing_key is None:
        with open(cfg["Security"]["private_key"], "rb") as kf:
            signing_key = serialization.load_pem_private_key(
                kf.read(), password=None, backend=default_backend())
    sig = signing_key.sign(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode(),
        padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(sig).decode()
    if corrupt_sig:
        raw = bytearray(base64.b64decode(sig_b64))
        raw[0] ^= 0xFF  # flip a byte so the server's signature check fails
        sig_b64 = base64.b64encode(bytes(raw)).decode()
    return {"body": body, "client_signature": sig_b64}


def _signed_checkin_request(cfg, id_resp, fn, mn, ln, *, client_id=None,
                            signing_key=None, corrupt_sig=False):
    """Build a check-in request from an honest VVID. Keyword overrides let
    callers forge the claimed client_id, sign with another client's key, or
    corrupt the signature (to force a server-side reject)."""
    body = {
        "client_id_num": int(cfg["Basic"]["client_id"]) if client_id is None else int(client_id),
        "timestamp": int(time.time() * 1000),
        "first_name": fn,
        "middle_name": mn,
        "last_name": ln,
        "voter_unique_id": id_resp["voter_unique_id"],
        "verified_id_message": id_resp,
    }
    return _sign_checkin_body(cfg, body, signing_key=signing_key, corrupt_sig=corrupt_sig)


def honest_checkin_once(cfg, voters, label):
    """One honest Phase-1 check-in (ID -> check-in) on fresh sockets, recording
    its check-in latency under `checkin_<label>` (and the ID latency under
    `id_<label>`). Phase 1 only — the ticket is NOT forwarded to the trusted
    device, since the server's check-in reaction is what we measure. Returns the
    check-in elapsed_ms, or None on a setup/ID error."""
    voter = random.choice(voters)
    vs = cs = None
    try:
        vs, cs = create_tls_sockets(cfg)
        fn, mn, ln = voter["first_name"], voter["middle_name"], voter["last_name"]
        id_req = build_voter_id_request(cfg, fn, mn, ln, voter["id"])
        id_resp, _ = _timed_request(vs, id_req, receive_voter_id,
                                    f"id_{label}", {"voter_id": voter["id"]})
        if not id_resp or "voter_unique_id" not in id_resp:
            return None
        req = _signed_checkin_request(cfg, id_resp, fn, mn, ln)
        _, ms = _timed_request(cs, req, receive_checkin_response,
                               f"checkin_{label}", {"voter_id": voter["id"]})
        return ms
    except Exception as exc:
        print(f"[honest:{label}] error: {exc}")
        return None
    finally:
        for s in (vs, cs):
            try:
                if s:
                    s.close()
            except Exception:
                pass


# Pool the 'mixed' aggressor draws from per request. Every entry produces a
# single forged check-in the server rejects (so the reaction is a real reject
# latency), and each sample's meta.attack records which one was drawn — so a
# mixed run disaggregates per attack in analysis. Excludes flood-honest (not an
# attack), withhold-token (no Phase-1 reject reaction), and stale/delayed-replay
# (built-in multi-second waits that would distort reaction latency).
AGGRESSOR_RANDOM_POOL = ["spoofed-client-id", "garbage", "simple-replay",
                         "cross-identity", "tampered-body"]


def aggressor_send_once(cfg, attack_mode, voters, measure_label):
    """Open fresh sockets and drive one aggressor check-in of the given kind,
    recording the *server reaction* (the offending check-in request) under
    `measure_label`. Supported attack_mode values:
        spoofed-client-id : body claims the alt client_id, signed with its key
        garbage           : valid body, corrupted client signature (forces reject)
        simple-replay     : a genuine check-in followed by a replay (the replay
                            is the measured request)
        cross-identity    : body claims voter B's UID/name but embeds voter A's
                            signed VVID (UID cross-check)
        tampered-body     : sign for voter A, rewrite body to voter B without
                            re-signing (client-signature integrity)
        flood-honest      : a fully valid check-in (pure load, no attack path)
        mixed             : pick a random attack from AGGRESSOR_RANDOM_POOL each
                            call (recorded per sample in meta.attack)
    Returns elapsed_ms for the measured request, or None on a setup error."""
    if attack_mode == "mixed":
        attack_mode = random.choice(AGGRESSOR_RANDOM_POOL)
    voter = random.choice(voters)
    # second, distinct voter for the identity-mismatch attacks
    voter2 = random.choice(voters)
    while len(voters) > 1 and voter2["id"] == voter["id"]:
        voter2 = random.choice(voters)
    fn, mn, ln = voter["first_name"], voter["middle_name"], voter["last_name"]
    vs = cs = replay_sock = None
    try:
        vs, cs = create_tls_sockets(cfg)
        measure_sock = cs  # socket the measured request is sent on
        id_req = build_voter_id_request(cfg, fn, mn, ln, voter["id"])
        id_resp, _ = _timed_request(vs, id_req, receive_voter_id,
                                    "aggressor_id",
                                    {"voter_id": voter["id"], "attack": attack_mode})
        if not id_resp or "voter_unique_id" not in id_resp:
            return None

        if attack_mode == "spoofed-client-id":
            key = _load_alt_private_key(cfg, RACE_ALT_PRIVATE_KEY)
            req = _signed_checkin_request(cfg, id_resp, fn, mn, ln,
                                          client_id=RACE_ALT_CLIENT_ID, signing_key=key)
        elif attack_mode == "garbage":
            req = _signed_checkin_request(cfg, id_resp, fn, mn, ln, corrupt_sig=True)
        elif attack_mode == "cross-identity":
            # claim voter2's UID/name but embed voter's (real) signed VVID
            body = {
                "client_id_num": int(cfg["Basic"]["client_id"]),
                "timestamp": int(time.time() * 1000),
                "first_name": voter2["first_name"],
                "middle_name": voter2["middle_name"],
                "last_name": voter2["last_name"],
                "voter_unique_id": voter2["id"],   # claimed victim (status-table key)
                "verified_id_message": id_resp,    # real voter's signed ID proof
            }
            req = _sign_checkin_body(cfg, body)    # validly signed by us
        elif attack_mode == "tampered-body":
            # sign an honest body for voter, then rewrite it to voter2 unsigned
            req = _signed_checkin_request(cfg, id_resp, fn, mn, ln)
            req["body"]["voter_unique_id"] = voter2["id"]
            req["body"]["first_name"] = voter2["first_name"]
            req["body"]["middle_name"] = voter2["middle_name"]
            req["body"]["last_name"] = voter2["last_name"]
        elif attack_mode == "simple-replay":
            req = _signed_checkin_request(cfg, id_resp, fn, mn, ln)
            # genuine first check-in on this socket...
            _timed_request(cs, req, receive_checkin_response,
                           "aggressor_replay_first",
                           {"voter_id": voter["id"], "attack": attack_mode})
            # ...then replay the IDENTICAL signed request on a FRESH socket, since
            # the server closes the connection after each single-use response (a
            # same-socket replay just hits a closed socket, measuring nothing).
            replay_sock = create_checkin_socket(cfg)
            measure_sock = replay_sock
        else:  # flood-honest
            req = _signed_checkin_request(cfg, id_resp, fn, mn, ln)

        _, ms = _timed_request(measure_sock, req, receive_checkin_response, measure_label,
                               {"voter_id": voter["id"], "attack": attack_mode})
        return ms
    except Exception as exc:
        print(f"[aggressor:{attack_mode}] error: {exc}")
        return None
    finally:
        for s in (vs, cs, replay_sock):
            try:
                if s:
                    s.close()
            except Exception:
                pass


class _BackgroundLoad:
    """Run `target(stop_event)` repeatedly across `n_workers` daemon threads
    until stop() is called. Used to generate steady cross-traffic against the
    shared server while the main thread measures a subject."""

    def __init__(self, target, n_workers, delay=0.0, name="load"):
        self._target = target
        self._n = max(0, int(n_workers))
        self._delay = delay
        self._name = name
        self._stop = threading.Event()
        self._threads = []
        self._completed = 0
        self._lock = threading.Lock()

    def _run(self):
        while not self._stop.is_set():
            try:
                self._target(self._stop)
            except Exception as exc:
                print(f"[{self._name}] worker error: {exc}")
            with self._lock:
                self._completed += 1
            if self._delay > 0:
                self._stop.wait(self._delay)

    def start(self):
        for _ in range(self._n):
            t = threading.Thread(target=self._run, daemon=True)
            t.start()
            self._threads.append(t)
        return self

    @property
    def completed(self):
        with self._lock:
            return self._completed

    def stop(self):
        self._stop.set()
        for t in self._threads:
            t.join(timeout=10.0)


def _summarize(name, samples):
    """Print and return min/mean/p50/p95/max over the non-None samples (ms)."""
    vals = sorted(s for s in samples if s is not None)
    if not vals:
        print(f"[{name}] no successful samples")
        return None
    n = len(vals)
    mean = sum(vals) / n
    p50 = vals[n // 2]
    p95 = vals[min(n - 1, int(round(0.95 * (n - 1))))]
    p99 = vals[min(n - 1, int(round(0.99 * (n - 1))))]
    stats = {"n": n, "min": vals[0], "mean": mean, "p50": p50,
             "p95": p95, "p99": p99, "max": vals[-1]}
    print(f"[{name}] n={n} min={stats['min']:.1f} mean={mean:.1f} "
          f"p50={p50:.1f} p95={p95:.1f} p99={p99:.1f} max={stats['max']:.1f} ms")
    return stats


def _parse_sweep(s):
    """Parse a comma-separated level list like '0,1,2,4,8' into [0,1,2,4,8].
    Returns None if empty/unset (caller then runs the single-point variant)."""
    if not s:
        return None
    return [int(tok) for tok in s.split(",") if tok.strip() != ""]


def mode_attacker_reaction_under_load(cfg, voters, attack_mode, honest_workers,
                                      samples, warmup, load_delay):
    """TEST BED 1 — reaction time of a misbehaving client while the server is
    busy serving honest voters. Honest worker threads generate steady load;
    we then fire `samples` aggressor check-ins and record how fast the server
    reacts to each (phase 'attacker_reaction')."""
    print(f"=== attacker-reaction-under-load: attack={attack_mode} "
          f"honest_workers={honest_workers} samples={samples} warmup={warmup}s ===")
    load = _BackgroundLoad(
        target=lambda stop: honest_checkin_once(cfg, voters, "honest_load"),
        n_workers=honest_workers, delay=load_delay, name="honest-load").start()
    reaction = []
    try:
        print(f"warming honest load for {warmup:.1f}s...")
        time.sleep(warmup)
        print(f"honest check-ins issued during warmup: {load.completed}")
        for i in range(samples):
            ms = aggressor_send_once(cfg, attack_mode, voters, "attacker_reaction")
            if ms is not None:
                print(f"  reaction[{i + 1}/{samples}] = {ms:.1f} ms")
                reaction.append(ms)
    finally:
        load.stop()
    print(f"honest check-ins completed under contention: {load.completed}")
    stats = _summarize("attacker_reaction", reaction)
    sys.exit(0 if stats else 2)


def mode_honest_latency_under_attack(cfg, voters, attack_mode, aggressor_workers,
                                     samples, warmup, load_delay):
    """TEST BED 2 — check-in latency an honest voter experiences with vs.
    without a concurrent attack. First a no-contention baseline
    (phase 'checkin_honest_baseline'), then aggressor workers start and we
    measure again (phase 'checkin_honest_under_attack'). Prints the delta."""
    print(f"=== honest-latency-under-attack: attack={attack_mode} "
          f"aggressor_workers={aggressor_workers} samples={samples} warmup={warmup}s ===")

    print(f"[baseline] measuring {samples} honest check-ins with NO attacker...")
    baseline = [honest_checkin_once(cfg, voters, "honest_baseline") for _ in range(samples)]
    b_stats = _summarize("honest_baseline", baseline)

    load = _BackgroundLoad(
        target=lambda stop: aggressor_send_once(cfg, attack_mode, voters, "aggressor_load"),
        n_workers=aggressor_workers, delay=load_delay, name="aggressor-load").start()
    under = []
    try:
        print(f"warming {attack_mode} attack load for {warmup:.1f}s...")
        time.sleep(warmup)
        print(f"aggressor requests issued during warmup: {load.completed}")
        print(f"[under-attack] measuring {samples} honest check-ins WHILE attacked...")
        under = [honest_checkin_once(cfg, voters, "honest_under_attack") for _ in range(samples)]
    finally:
        load.stop()
    print(f"aggressor requests completed: {load.completed}")
    u_stats = _summarize("honest_under_attack", under)

    if b_stats and u_stats:
        dp50 = u_stats["p50"] - b_stats["p50"]
        ratio = (u_stats["p50"] / b_stats["p50"]) if b_stats["p50"] else float("inf")
        print(f"=== COLLATERAL IMPACT: honest check-in p50 {b_stats['p50']:.1f}ms -> "
              f"{u_stats['p50']:.1f}ms (delta {dp50:+.1f}ms, {ratio:.2f}x) "
              f"under {attack_mode} attack ===")
    sys.exit(0 if (b_stats and u_stats) else 2)


def mode_attacker_reaction_sweep(cfg, voters, attack_mode, levels, samples,
                                 warmup, load_delay):
    """TEST BED 1 (sweep) — attacker reaction time vs offered honest load.
    For each level K in `levels`, run K honest worker threads, then measure
    `samples` aggressor reaction times under phase 'attacker_reaction_load{K}'.
    The plotter turns these into a reaction-vs-load curve."""
    print(f"=== attacker-reaction-under-load SWEEP: attack={attack_mode} "
          f"honest-load levels={levels} samples={samples} warmup={warmup}s ===")
    any_ok = False
    for k in levels:
        print(f"--- load level: {k} honest workers ---")
        load = _BackgroundLoad(
            target=lambda stop: honest_checkin_once(cfg, voters, "honest_load"),
            n_workers=k, delay=load_delay, name=f"honest-load-{k}").start()
        reaction = []
        try:
            time.sleep(warmup if k else 0)
            print(f"  honest check-ins issued during warmup: {load.completed}")
            for _ in range(samples):
                ms = aggressor_send_once(cfg, attack_mode, voters,
                                         f"attacker_reaction_load{k}")
                if ms is not None:
                    reaction.append(ms)
        finally:
            load.stop()
        if _summarize(f"attacker_reaction_load{k}", reaction):
            any_ok = True
    sys.exit(0 if any_ok else 2)


def mode_honest_latency_sweep(cfg, voters, attack_mode, levels, samples,
                              warmup, load_delay):
    """TEST BED 2 (sweep) — honest check-in latency vs background intensity,
    with a LOAD-MATCHED HONEST CONTROL so an effect can be attributed to the
    attack rather than to raw added traffic. For each level K:
      * attack series  : K aggressor workers -> phase 'checkin_honest_attack{K}'
      * control series : K EXTRA honest workers (same volume, benign path)
                         -> phase 'checkin_honest_control{K}'
    K=0 is a clean no-load baseline for each series. Amplification at a level is
    attack_p50 / control_p50: >1 means the attack costs more than its volume."""
    print(f"=== honest-latency-under-attack SWEEP: attack={attack_mode} "
          f"intensity levels={levels} samples={samples} warmup={warmup}s "
          f"(attack vs load-matched honest control) ===")
    any_ok = False
    for k in levels:
        print(f"--- intensity level: {k} ---")
        # Attack series: K aggressor workers competing with the measured honest voter.
        load = _BackgroundLoad(
            target=lambda stop: aggressor_send_once(cfg, attack_mode, voters, "aggressor_load"),
            n_workers=k, delay=load_delay, name=f"aggressor-{k}").start()
        try:
            time.sleep(warmup if k else 0)
            attack = [honest_checkin_once(cfg, voters, f"honest_attack{k}")
                      for _ in range(samples)]
        finally:
            load.stop()
        sa = _summarize(f"checkin_honest_attack{k}", attack)

        # Control series: K EXTRA honest workers — same request volume, benign path.
        load = _BackgroundLoad(
            target=lambda stop: honest_checkin_once(cfg, voters, "control_load"),
            n_workers=k, delay=load_delay, name=f"control-{k}").start()
        try:
            time.sleep(warmup if k else 0)
            control = [honest_checkin_once(cfg, voters, f"honest_control{k}")
                       for _ in range(samples)]
        finally:
            load.stop()
        sc = _summarize(f"checkin_honest_control{k}", control)

        if sa and sc:
            any_ok = True
            if sc["p50"]:
                amp = sa["p50"] / sc["p50"]
                print(f"  [lvl {k}] AMPLIFICATION attack_p50/control_p50 = {amp:.2f}x "
                      f"(attack {sa['p50']:.1f}ms vs control {sc['p50']:.1f}ms)")
    sys.exit(0 if any_ok else 2)


def mode_fleet_contention(cfg, voters, attack_mode, attacker_id):
    """FLEET test bed — one compromised client among a real deployed crowd.

    Every untrusted client in the fleet runs THIS same command; the harness
    (stress_test --runs/--parallel across all --untrusted services) drives the
    honest crowd's load. Each container branches on its OWN client_id:

      * if my client_id == attacker_id -> run one aggressor attack of
        `attack_mode`, recording the server reaction under 'attacker_reaction'.
      * otherwise -> run one honest check-in, recording its latency under
        'checkin_honest_under_attack' (when an attacker is designated) or
        'checkin_honest_baseline' (attacker_id < 0, i.e. an all-honest run).

    So a single fleet run yields the attacker's reaction time AND the honest
    crowd's check-in latency, with real distinct client identities. Run it twice
    — once with --attacker-id <victim> and once with --attacker-id -1 — to get
    the under-attack vs baseline pair the plotter compares.

    Unlike the threaded test beds, the contention here scales with how many
    clients you deploy and the harness --parallel, not with internal threads."""
    my_id = int(cfg["Basic"]["client_id"])
    if attacker_id >= 0 and my_id == attacker_id:
        print(f"[fleet] client {my_id} is the COMPROMISED client "
              f"(attack={attack_mode})")
        ms = aggressor_send_once(cfg, attack_mode, voters, "attacker_reaction")
        if ms is None:
            print("[fleet] INCONCLUSIVE: aggressor request did not complete")
            sys.exit(2)
        print(f"[fleet] attacker reaction = {ms:.1f} ms")
        sys.exit(0)

    label = "honest_under_attack" if attacker_id >= 0 else "honest_baseline"
    ms = honest_checkin_once(cfg, voters, label)
    if ms is None:
        print(f"[fleet] client {my_id} honest check-in did not complete")
        sys.exit(2)
    print(f"[fleet] client {my_id} honest check-in ({label}) = {ms:.1f} ms")
    sys.exit(0)


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
        choices=["honest", "simple-replay", "stale-replay", "ticket-substitution", "race-condition", "cross-identity", "tampered-body", "spoofed-client-id", "delayed-replay", "withhold-token", "attacker-reaction-under-load", "honest-latency-under-attack", "fleet-contention"],
        default="honest",
        help="Client behavior to emulate (default: honest).",
    )
    parser.add_argument(
        "--attack-mode",
        choices=["spoofed-client-id", "garbage", "simple-replay", "cross-identity",
                 "tampered-body", "flood-honest", "mixed"],
        default="spoofed-client-id",
        help="Which misbehaviour the aggressor runs in the contention test beds "
             "(attacker-reaction-under-load / honest-latency-under-attack). "
             "'mixed' draws a random attack per request (recorded in meta.attack). "
             "Default: spoofed-client-id.",
    )
    parser.add_argument(
        "--honest-workers", type=int, default=4,
        help="Background honest check-in worker threads in "
             "attacker-reaction-under-load (default: 4).",
    )
    parser.add_argument(
        "--aggressor-workers", type=int, default=2,
        help="Background aggressor worker threads in "
             "honest-latency-under-attack (default: 2).",
    )
    parser.add_argument(
        "--samples", type=int, default=20,
        help="Measured requests per phase in the contention test beds "
             "(default: 20).",
    )
    parser.add_argument(
        "--warmup", type=float, default=3.0,
        help="Seconds to let background load reach steady state before "
             "measuring, in the contention test beds (default: 3.0).",
    )
    parser.add_argument(
        "--load-delay", type=float, default=0.0,
        help="Per-iteration sleep (seconds) inside each background load worker "
             "to throttle the cross-traffic rate (default: 0.0 = full rate).",
    )
    parser.add_argument(
        "--attacker-id", type=int, default=-1,
        help="In fleet-contention mode, the client_id of the single COMPROMISED "
             "untrusted client; every other client behaves honestly. -1 (default) "
             "means an all-honest baseline run (no attacker). Pick it at random "
             "from your deployed untrusted ids to target a random victim.",
    )
    parser.add_argument(
        "--sweep", type=str, default="",
        help="Comma-separated levels to sweep in the contention test beds, e.g. "
             "'0,1,2,4,8,16'. For attacker-reaction-under-load each level is a "
             "honest-worker count (x-axis = load); for honest-latency-under-attack "
             "each level is a background intensity, run as both an attack series and "
             "a load-matched honest control. Empty = single-point (no sweep).",
    )
    parser.add_argument(
        "--stale-delay",
        type=float,
        default=120.0,
        help="Seconds to wait before replay in stale-replay mode (default: 120s).",
    )
    parser.add_argument(
        "--replay-delay",
        type=float,
        default=8.0,
        help="Seconds to wait before reusing the stored ID image in delayed-replay mode "
             "(default: 8s; must exceed the 5s ID-server freshness window).",
    )
    parser.add_argument(
        "--withhold-wait",
        type=float,
        default=70.0,
        help="Seconds to withhold the ticket before re-attempting a legitimate "
             "check-in in withhold-token mode (default: 70s; must exceed the "
             "check-in server's TIMEOUT_INTERVAL, min 1 minute = 60s). Set "
             "--timeout-per-run on stress_test.py higher than this.",
    )
    args = parser.parse_args()

    cfg = load_config(str(args.cfg_file))
    global SERVICE_NAME
    SERVICE_NAME = f"untrusted-client-{cfg['Basic']['client_id']}"
    voters_csv = Path(cfg["Basic"]["voters_csv"])

    voters = load_voters_csv(voters_csv)
    if not voters:
        print("No voters loaded from CSV")
        sys.exit(1)

    # Modes that open their own per-request sockets (the threaded test beds,
    # fleet-contention, race-condition) must NOT eagerly connect here: with a
    # multi-container fleet, every client doing a pointless simultaneous handshake
    # at startup overruns the single-threaded serial-accept server (ECONNREFUSED),
    # and this top-level connect is not exception-guarded so it crashes the run.
    SELF_SOCKET_MODES = ("race-condition", "attacker-reaction-under-load",
                         "honest-latency-under-attack", "fleet-contention")
    if args.mode in SELF_SOCKET_MODES:
        voter_sock = checkin_sock = None
    else:
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

    elif args.mode == "cross-identity":
        voter_victim, voter_real = pick_two_distinct_voters(voters)
        attack_cross_identity(cfg, voter_sock, checkin_sock, voter_victim, voter_real)

    elif args.mode == "tampered-body":
        voter_a, voter_b = pick_two_distinct_voters(voters)
        attack_tampered_body(cfg, voter_sock, checkin_sock, voter_a, voter_b)

    elif args.mode == "spoofed-client-id":
        v = random.choice(voters)
        attack_spoofed_client_id(cfg, voter_sock, checkin_sock, v)

    elif args.mode == "delayed-replay":
        v = random.choice(voters)
        attack_delayed_replay(cfg, voter_sock, checkin_sock, v, delay_seconds=args.replay_delay)

    elif args.mode == "withhold-token":
        v = random.choice(voters)
        attack_withhold_token(cfg, voter_sock, checkin_sock, v, withhold_wait=args.withhold_wait)

    elif args.mode == "race-condition":
        v = random.choice(voters)
        attack_race_condition(cfg, v)
        return

    elif args.mode == "attacker-reaction-under-load":
        # These test beds open their own per-request sockets in worker threads.
        levels = _parse_sweep(args.sweep)
        if levels:
            mode_attacker_reaction_sweep(
                cfg, voters, args.attack_mode, levels,
                args.samples, args.warmup, args.load_delay)
        else:
            mode_attacker_reaction_under_load(
                cfg, voters, args.attack_mode, args.honest_workers,
                args.samples, args.warmup, args.load_delay)
        return

    elif args.mode == "honest-latency-under-attack":
        levels = _parse_sweep(args.sweep)
        if levels:
            mode_honest_latency_sweep(
                cfg, voters, args.attack_mode, levels,
                args.samples, args.warmup, args.load_delay)
        else:
            mode_honest_latency_under_attack(
                cfg, voters, args.attack_mode, args.aggressor_workers,
                args.samples, args.warmup, args.load_delay)
        return

    elif args.mode == "fleet-contention":
        # Role-aware: every deployed untrusted client runs this; one is the
        # attacker, the rest are the honest crowd. The harness drives the load.
        mode_fleet_contention(cfg, voters, args.attack_mode, args.attacker_id)
        return

    voter_sock.close()
    checkin_sock.close()


if __name__ == "__main__":
    main()
