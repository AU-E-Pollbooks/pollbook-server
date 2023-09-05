#!/usr/bin/python3

import socket
import json
import time
from signedjson.key import generate_signing_key, get_verify_key
from signedjson.sign import (
    sign_json, verify_signed_json, SignatureVerifyException
)

ID_SERVICE_HOST = "localhost"
ID_SERVICE_PORT = 9999

CHECKIN_SERVICE_HOST = "localhost"
CHECKIN_SERVICE_PORT = 9998

SIGNING_KEY = generate_signing_key('PLACEHOLDER')

class InvalidRequestType(Exception):
    "Raised when the type is unknown"
    pass

class InvalidVoterCheckIn(Exception):
    "Raised when the voter check-in is invalid"
    pass

class InvalidVoterID(Exception):
    "Raised when the voter identification is invalid"
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
            voterIdResponse = json.loads(received)
            client_id_num = voterIdResponse["body"]["client_id_num"]
            timestamp = voterIdResponse["body"]["timestamp"]
            voter_id_data = voterIdResponse["body"]["voter_id_data"]
            voter_unique_id = voterIdResponse["voter_unique_id"]
            id_service_signature = voterIdResponse["id_service_signature"]
            print("Identification Service Response: " + "\n" + client_id_num + "\n" + timestamp + "\n" + voter_id_data + "\n" + voter_unique_id + "\n" + id_service_signature)
            """
            if approvedVal == "True":
                print("Voter Identification Approved!")
            else:
                raise InvalidVoterID
            """
        elif type == "voterCheckin":
            voterCheckInResponse = json.loads(received)
            approvedVal = voterCheckInResponse["body"]["approved"]
            req_client_id = voterCheckInResponse["body"]["requesting_client_id"]
            timestamp = voterCheckInResponse["body"]["timestamp"]
            last_name = voterCheckInResponse["body"]["last_name"]
            first_name = voterCheckInResponse["body"]["first_name"]
            middle_name = voterCheckInResponse["body"]["middle_name"]
            voter_unique_id = voterCheckInResponse["body"]["voter_unique_id"]
            checkin_service_signature = voterCheckInResponse["checkin_service_signature"]
            if approvedVal == "True":
                print("Voter Check-In Approved!")
                print("Check-In Service Response: " + "\n" + req_client_id + "\n" + timestamp + "\n" + last_name + "\n" + first_name + "\n" + middle_name + "\n" + voter_unique_id + "\n" + checkin_service_signature)
            else:
                raise InvalidVoterCheckIn

        else:
            raise InvalidRequestType
    
    except InvalidRequestType:
        print("Exception occurred: Unknown Request Type")

    except InvalidVoterCheckIn:
        print("Exception occurred: Invalid Voter Check-In")

"""
Voter ID Service API

Input:
    base64 encoded voter_id_data
    client_id_num

Request: 
    ["body":["client_id_num", "timestamp", "voter_id_data"], "client_signature"]

Response: 
    ["body":["client_id_num", "timestamp", "voter_id_data"], "voter_unique_id", "id_service_signature"]

===========================================================================

Key Signing Example (Source: https://pypi.org/project/signedjson/)

signing_key = generate_signing_key('zxcvb')
signed_json = sign_json({'my_key': 'my_data'}, 'Alice', signing_key)

verify_key = get_verify_key(signing_key)

try:
    verify_signed_json(signed_json, 'Alice', verify_key)
    print 'Signature is valid'
except SignatureVerifyException:
    print 'Signature is invalid'
"""

def request_Voter_ID_Service(client_id_num, voter_id_data):
    timestamp = int(time.time())
    client_signature = sign_json({"client_id_num": client_id_num, "timestamp": timestamp, "voter_id_data": voter_id_data}, client_id_num, SIGNING_KEY)
    m = {"body": {"client_id_num": client_id_num, "timestamp": timestamp, "voter_id_data": voter_id_data}, "client_signature": client_signature}
    data = json.dumps(m)
    send_JSON(data, "voterID", ID_SERVICE_HOST, ID_SERVICE_PORT)

"""
Voter Checkin Service API

Request: 
    ["body":["client_id_num", "timestamp", "last_name", "first_name", "middle_name", "voter_unique_id", "verified_id_message"], "client_signature"]

Response: 
    ["body":["approved", "requesting_client_id", "timestamp", "last_name", "first_name", "middle_name", "voter_unique_id"], "checkin_service_signature"]

===========================================================================

Key Signing Example (Source: https://pypi.org/project/signedjson/)

signing_key = generate_signing_key('zxcvb')
signed_json = sign_json({'my_key': 'my_data'}, 'Alice', signing_key)

verify_key = get_verify_key(signing_key)

try:
    verify_signed_json(signed_json, 'Alice', verify_key)
    print 'Signature is valid'
except SignatureVerifyException:
    print 'Signature is invalid'
"""

def request_Checkin_Service(client_id_num, timestamp, last_name, first_name, middle_name, voter_unique_id, verified_id_message):
    timestamp = int(time.time())
    client_signature = sign_json({"client_id_num": client_id_num, "timestamp": timestamp, "last_name": last_name, "first_name": first_name, "middle_name": middle_name, "voter_unique_id": voter_unique_id, "verified_id_message": verified_id_message}, client_id_num, SIGNING_KEY)
    m = {"body": {"client_id_num": client_id_num, "timestamp": timestamp, "last_name": last_name, "first_name": first_name, "middle_name": middle_name, "voter_unique_id": voter_unique_id, "verified_id_message": verified_id_message}, "client_signature": client_signature}
    data = json.dumps(m)
    send_JSON(data, "voterCheckin", CHECKIN_SERVICE_HOST, CHECKIN_SERVICE_PORT)

def main():
    print("PLACEHOLDER")

if __name__ == "__main__":
    main()