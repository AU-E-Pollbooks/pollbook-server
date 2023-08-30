#!/usr/bin/python3

import socket
import json

ID_SERVICE_HOST = "localhost"
ID_SERVICE_PORT = 9999

CHECKIN_SERVICE_HOST = "localhost"
CHECKIN_SERVICE_PORT = 9998

class InvalidRequestType(Exception):
    "Raised when the type is unknown"
    pass

def send_JSON(data, type, host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        sock.sendall(bytes(data,encoding="utf-8"))

        received = sock.recv(1024)
        received = received.decode("utf-8")

    finally:
        sock.close()

    try:
        if type == "voterID":
            #TODO - Parse response: ["body":["client_id_num", "timestamp", "voter_id_data"], "voter_unique_id", "id_service_signature"]
            print("Voter ID Response PLACEHOLDER")

        elif type == "voterCheckin":
            # TODO - Parse response: ["body":["approved", "requesting_client_id", "timestamp", "last_name", "first_name", "middle_name", "voter_unique_id"], "checkin_service_signature"]
            print("Voter Check-In Response PLACEHOLDER")

        else:
            raise InvalidRequestType
    
    except InvalidRequestType:
        print("Exception occurred: Unknown Request Type")

"""
Voter ID Service API

Request: 
    ["body":["client_id_num", "timestamp", "voter_id_data"], "client_signature"]

Response: 
    ["body":["client_id_num", "timestamp", "voter_id_data"], "voter_unique_id", "id_service_signature"]
"""

def request_Voter_ID_Service(client_id_num, timestamp, voter_id_data):
    # TODO - Create Client Signature
    client_signature = "PLACEHOLDER"
    m = {"body": {"client_id_num": client_id_num, "timestamp": timestamp, "voter_id_data": voter_id_data}, "client_signature": client_signature}
    data = json.dumps(m)
    send_JSON(data, "voterID", ID_SERVICE_HOST, ID_SERVICE_PORT)

"""
Voter Checkin Service API

Request: 
    ["body":["client_id_num", "timestamp", "last_name", "first_name", "middle_name", "voter_unique_id", "verified_id_message"], "client_signature"]

Response: 
    ["body":["approved", "requesting_client_id", "timestamp", "last_name", "first_name", "middle_name", "voter_unique_id"], "checkin_service_signature"]
"""

def request_Checkin_Service(client_id_num, timestamp, last_name, first_name, middle_name, voter_unique_id, verified_id_message):
    # TODO - Create Client Signature
    client_signature = "PLACEHOLDER"
    m = {"body": {"client_id_num": client_id_num, "timestamp": timestamp, "last_name": last_name, "first_name": first_name, "middle_name": middle_name, "voter_unique_id": voter_unique_id, "verified_id_message": verified_id_message}, "client_signature": client_signature}
    data = json.dumps(m)
    send_JSON(data, "voterCheckin", CHECKIN_SERVICE_HOST, CHECKIN_SERVICE_PORT)

def main():
    print("PLACEHOLDER")

if __name__ == "__main__":
    main()