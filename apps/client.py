import socket 
from collections import OrderedDict
import os
import time
import json
from pathlib import Path
import scapy
from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, sendp
import base64
import ssl
import configparser
import typing
from typing import Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import utils


class RSASigner:
    def __init__(self, private_key_path: str):
        with open(private_key_path, "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

    def sign(self, message: bytes) -> bytes:
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(message)
        digest = hasher.finalize()
        return self.private_key.sign(
            digest,
            padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA256())
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
                signature,
                self._buffer,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

class VoterIDRequest:

    class Body:
        def __init__(self,
                     client_id_num: int,
                     timestamp: int,
                     voter_id_data: Union[bytes, bytearray]): 
            self.client_id_num = client_id_num
            self.timestamp = timestamp
            self.voter_id_data = voter_id_data

        def to_json(self) -> OrderedDict:
            voter_id_bytes = bytes(self.voter_id_data)
            voter_id_b64 = base64.b64encode(voter_id_bytes).decode('utf-8')
            return OrderedDict([
                ("client_id_num", self.client_id_num),
                ("timestamp", self.timestamp),
                ("voter_id_data", voter_id_b64),
            ])

        @staticmethod
        def from_json(data: dict[str, any]) -> "VoterIDRequest.Body":
            voter_id_bytes = base64.b64decode(data["voter_id_data"])
            return VoterIDRequest.Body(
                client_id_num=data["client_id_num"],
                timestamp=data["timestamp"],
                voter_id_data=list(voter_id_bytes),
            )


    def __init__(self, body: "VoterIDRequest.Body", client_signature: bytearray):
        self.body = body
        self.client_signature = client_signature

    def to_json(self) -> OrderedDict:
        return OrderedDict([
            ("body", self.body.to_json()),
            ("client_signature", base64.b64encode(self.client_signature).decode('utf-8'))
        ])

    @staticmethod
    def from_json(data: dict[str, any]) -> "VoterIDRequest":
        body = VoterIDRequest.Body.from_json(data["body"])
        sig_bytes = bytearray(base64.b64decode(data["client_signature"]))
        return VoterIDRequest(
            body=body,
            client_signature=sig_bytes
        )

class VerifiedVoterID:
    def __init__(self,
                 presented_id: VoterIDRequest,
                 voter_unique_id: int,
                 id_service_signature: bytearray):
        self.presented_id = presented_id
        self.voter_unique_id = voter_unique_id
        self.id_service_signature = id_service_signature  

    def to_json(self) -> OrderedDict:
        return OrderedDict([
            ("id_service_signature", base64.b64encode(self.id_service_signature).decode('utf-8')),
            ("presented_id", self.presented_id.to_json()),
            ("voter_unique_id", self.voter_unique_id),
        ])

    @staticmethod
    def from_json(data: dict[str, any]) -> "VerifiedVoterID":
        presented_id = VoterIDRequest.from_json(data["presented_id"])
        voter_unique_id = data["voter_unique_id"]
        id_service_signature = base64.b64decode(data["id_service_signature"])
        return VerifiedVoterID(presented_id, voter_unique_id, id_service_signature)


class CheckinRequest:
    class Body:
        def __init__(self,
                     client_id_num: int,
                     first_name: str,
                     last_name: str,
                     middle_name: str,
                     timestamp: int,
                     verified_id_message: 'VerifiedVoterID',
                     voter_unique_id: int):
            self.client_id_num = client_id_num
            self.first_name = first_name
            self.last_name = last_name
            self.middle_name = middle_name
            self.timestamp = timestamp
            self.verified_id_message = verified_id_message
            self.voter_unique_id = voter_unique_id

        def to_json(self) -> OrderedDict:
            return OrderedDict([
                ("client_id_num", self.client_id_num),
                ("first_name", self.first_name),
                ("last_name", self.last_name),
                ("middle_name", self.middle_name),
                ("timestamp", self.timestamp),
                ("verified_id_message", self.verified_id_message.to_json()),
                ("voter_unique_id", self.voter_unique_id),
            ])

        @staticmethod
        def from_json(data: dict[str, any]) -> 'CheckinRequest.Body':
            return CheckinRequest.Body(
                client_id_num=data["client_id_num"],
                first_name=data["first_name"],
                last_name=data["last_name"],
                middle_name=data["middle_name"],
                timestamp=data["timestamp"],
                verified_id_message=VerifiedVoterID.from_json(data["verified_id_message"]),
                voter_unique_id=data["voter_unique_id"],
            )

    def __init__(self,
                 body: 'CheckinRequest.Body',
                 client_signature: bytearray):
        self.body = body
        self.client_signature = client_signature

    def to_json(self) -> dict[str, any]:
        return {
            "body": self.body.to_json(),
            "client_signature": base64.b64encode(self.client_signature).decode('utf-8')
        }

    @staticmethod
    def from_json(self, data: dict[str, any]) -> 'CheckinRequest':
        body = CheckinRequest.Body.from_json(data["body"])
        signature = bytearray(base64.b64decode(data["client_signature"]))
        return CheckinRequest(body, signature)


class CheckinResponse:
    class Body:
        def __init__(self,
                     approved: bool,
                     requesting_client_id: int,
                     timestamp: int,
                     last_name: str,
                     first_name: str,
                     middle_name: str,
                     voter_unique_id: int,
                     ticket: str):
            self.approved = approved
            self.requesting_client_id = requesting_client_id
            self.timestamp = timestamp
            self.last_name = last_name
            self.first_name = first_name
            self.middle_name = middle_name
            self.voter_unique_id = voter_unique_id
            self.ticket = ticket

        def to_json(self) -> dict[str, any]:
            return {
                "approved": self.approved,
                "requesting_client_id": self.requesting_client_id,
                "timestamp": self.timestamp,
                "last_name": self.last_name,
                "first_name": self.first_name,
                "middle_name": self.middle_name,
                "voter_unique_id": self.voter_unique_id,
                "ticket": self.ticket
            }

        @staticmethod
        def from_json(data: dict[str, any]) -> 'CheckinResponse.Body':
            return CheckinResponse.Body(
                approved=data["approved"],
                requesting_client_id=data["requesting_client_id"],
                timestamp=data["timestamp"],
                last_name=data["last_name"],
                first_name=data["first_name"],
                middle_name=data["middle_name"],
                voter_unique_id=data["voter_unique_id"],
                ticket=data["ticket"]
            )

    def __init__(self,
                 body: 'CheckinResponse.Body',
                 checkin_service_signature: bytearray):
        self.body = body
        self.checkin_service_signature = checkin_service_signature

    @staticmethod
    def to_json(self) -> dict[str, any]:
        return {
            "body": self.body.to_json(),
            "checkin_service_signature": base64.b64encode(self.checkin_service_signature).decode('utf-8')
        }

    @staticmethod
    def from_json(data: dict[str, any]) -> 'CheckinResponse':
        body = CheckinResponse.Body.from_json(data["body"])
        sig = bytearray(base64.b64decode(data["checkin_service_signature"]))
        return CheckinResponse(body, sig)


def load_config(config_relative_path: str) -> configparser.ConfigParser:
    config_path = Path(__file__).parent / config_relative_path
    config_path = config_path.resolve()

    config = configparser.ConfigParser()
    read_files = config.read(config_path)
    if not read_files:
        raise FileNotFoundError(f"Could not read config at {config_path}")

    if "Security" in config:
        base = config_path.parent  
        for key in ("local_cert", "private_key", "ca_cert"):
            if key in config["Security"]:
                val = config["Security"][key]
                path = Path(val)
                if not path.is_absolute():
                    abs_path = (base / path).resolve()
                    config["Security"][key] = str(abs_path)

    return config

def create_tls_context(certfile: str, keyfile: str, cafile: str) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


def tls_handshake(host: str, port: int, context: ssl.SSLContext, label: str) -> ssl.SSLSocket:
    sock = socket.create_connection((host, port))
    ssock = context.wrap_socket(sock, server_hostname=host)
    print(f"Handshake successful with {label} ({host}:{port})")
    return ssock

def create_tls_sockets(config):
    client_cert = config["Security"]["local_cert"]
    client_key = config["Security"]["private_key"]
    ca_file = config["Security"]["ca_cert"]

    print(f"CA file path: {ca_file}")
    print(f"Exists? {Path(ca_file).exists()}")

    context = create_tls_context(client_cert, client_key, ca_file)

    voter_host = config["Basic"]["id_service_host"]
    voter_port = int(config["Basic"]["id_service_port"])
    voter_socket = tls_handshake(voter_host, voter_port, context, "VoterServer")

    checkin_host = config["Basic"]["checkin_service_host"]
    checkin_port = int(config["Basic"]["checkin_service_port"])
    checkin_socket = tls_handshake(checkin_host, checkin_port, context, "CheckinServer")

    return voter_socket, checkin_socket, RSASigner(client_key)


def build_voter_id_request(config, signer):
    timestamp = int(time.time() * 1000)
    voter_id_data = bytearray(os.urandom(32))

    request_body = VoterIDRequest.Body(
        client_id_num=int(config["Basic"]["client_id"]),
        timestamp=timestamp,
        voter_id_data=voter_id_data
    )

    request_bytes = json.dumps(request_body.to_json(), separators=(",", ":")).encode()
    signature = signer.sign(request_bytes)

    return VoterIDRequest(request_body, signature)

def send_request(socket, request):
    msg = json.dumps(request.to_json(), separators=(",",":"), ensure_ascii=False).encode("utf-8")
    msg_len = str(len(msg)).encode('utf-8')
    socket.sendall(msg_len + b'\n' + msg + b'\n')

def send_checkin_request(socket, request):
    msg = json.dumps(request.to_json(), separators=(",",":"), ensure_ascii=False).encode('utf-8')
    print(msg)
    msg_len = str(len(msg)).encode('utf-8')
    socket.sendall(msg_len + b'\n' + msg + b'\n')

def verify_signature(public_key_path, message: bytes, signature: bytes):
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature valid")
    except Exception as e:
        print("Signature invalid:", e)

def receive_length_prefixed_json(socket: ssl.SSLSocket) -> dict:
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


def build_checkin_request(config, signer, voter_unique_id: int,
                          first_name: str, middle_name: str, last_name: str,
                          verified_id: VerifiedVoterID) -> CheckinRequest:
    timestamp = int(time.time() * 1000)

    body = CheckinRequest.Body(
        client_id_num=int(config["Basic"]["client_id"]),
        timestamp=timestamp,
        first_name=first_name,
        middle_name=middle_name,
        last_name=last_name,
        voter_unique_id=voter_unique_id,
        verified_id_message=verified_id
    )

    body_bytes = json.dumps(body.to_json(), separators=(", ", ": "), ensure_ascii=False).encode('utf-8')
    signature = signer.sign(body_bytes)
    print("Python signed bytes (base64):", base64.b64encode(body_bytes).decode())

    return CheckinRequest(body, signature)

def get_checkin_response_signing_bytes(resp: CheckinResponse) -> bytes:
    return json.dumps(resp.body.to_json(), separators=(",", ":")).encode()

def receive_checkin_response(sock: ssl.SSLSocket) -> CheckinResponse:
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

    return CheckinResponse.from_json(payload)

def verify_checkin_signature(config, response: CheckinResponse):
    verifier = RSAVerifier(config["Security"]["checkin_service_public_key"])
    verifier.init()
    verifier.add_bytes(get_checkin_response_signing_bytes(response))
    return verifier.finalize(response.checkin_service_signature)



def main():
    config = load_config("docker-test-deployment/client0/client_config.ini")
    voter_socket, checkin_socket, signer = create_tls_sockets(config)
    verifier = RSAVerifier("id_pubkey.pem")


    print("Enter Voter Information:")
    voter_id = int(input("Voter ID: "))
    first_name = input("First Name: ")
    middle_name = input("Middle Name: ")
    last_name = input("Last Name: ")


    request = build_voter_id_request(config, signer)
    send_request(voter_socket, request)

    resp_data = receive_length_prefixed_json(voter_socket)
    verified_voter_id = VerifiedVoterID.from_json(resp_data)
    partial = {
        "presented_id": verified_voter_id.presented_id.to_json(),
        "voter_unique_id": verified_voter_id.voter_unique_id
    }
    vvid = json.dumps(partial, separators=(",", ":")).encode()

    verifier.init()

    verifier.add_bytes(vvid)
    if verifier.finalize(verified_voter_id.id_service_signature):
        print("Signature from ID service is valid")
    else:
        print("Invalid signature from ID service")
        return

    client_key = config["Security"]["private_key"]
    signer2 = RSASigner(client_key)
    checkin_request = build_checkin_request(
        config,
        signer2,
        verified_voter_id.voter_unique_id,
        first_name,
        middle_name,
        last_name,
        verified_voter_id
    )

    send_checkin_request(checkin_socket, checkin_request)
    response = receive_checkin_response(checkin_socket)

    if verify_checkin_signature(config, response):
        print("Checkin server signature verified.")
        print("Ticket:", response.body.ticket)
        print("Approved:", response.body.approved)
    else:
        print("Invalid signature from CheckinServer")


if __name__ == "__main__":
    main()


