#pragma once

#include "voter_id_request.hpp"
#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>
#include "openssl/base64.hpp"


// namespace nlohmann {
//     inline void to_json(json& j, const Client& client) {
//         switch (client) {
//             case Client::FirstClient: j = "FirstClient"; break;
//             case Client::SecondClient: j = "SecondClient"; break;
//         }
//     }
//
//     inline void from_json(const json& j, Client& client) {
//         std::string s = j.get<std::string>();
//         if (s == "FirstClient") 
//             client = Client::FirstClient;
//         else if (s == "SecondClient") 
//             client = Client::SecondClient;
//         else 
//             throw std::runtime_error("Invalid client type");
//     }
// }

namespace epollbook {

/**
 * A message to be sent over the network from a pollbook client to the Check-in
 * Service when it makes a request to check in a particular voter.
 */
struct CheckinRequest {
    /**
     * This inner struct defines the "body" fields of the request message,
     * which is everything except the signature. The outer struct contains
     * one Body instance and the signature.
     */
    struct Body {
        /**
         * A unique number identifying the client in this system. This is used (for
         * now) instead of a hostname or IP address to match clients to public keys.
         */
        std::uint32_t client_id_num;
        /**
         * The time, as a system-clock timestamp in milliseconds, when the client
         * issued this request. Requests are only valid if their timestamp is
         * relatively recent, although there will obviously be a small amount of
         * clock drift between clients.
         */
        std::uint64_t timestamp;
        /** The voter's last name */
        std::string last_name;
        /** The voter's first name */
        std::string first_name;
        /** The voter's middle name */
        std::string middle_name;
        /**
         * The unique ID number identifying this voter within the pollbook system, as
         * agreed upon by the pollbook system and the voter ID service.
         */
        std::uint32_t voter_unique_id;
        /**
         * The verification message the client received from the voter ID service,
         * asserting that this voter has a valid ID. It should contain a valid
         * signature from the voter ID service and the same unique voter ID as the
         * one in this check-in request.
         */
        VerifiedVoterID verified_id_message;
        Body(std::uint32_t client_id_num, std::uint64_t timestamp,
             const std::string& last_name,
             const std::string& first_name,
             const std::string& middle_name,
             std::uint32_t voter_unique_id,
             const VerifiedVoterID& verified_id_message)
                : client_id_num(client_id_num),
                  timestamp(timestamp),
                  last_name(last_name),
                  first_name(first_name),
                  middle_name(middle_name),
                  voter_unique_id(voter_unique_id),
                  verified_id_message(verified_id_message) {}

        static nlohmann::json ToJson(const CheckinRequest::Body& body) {
            nlohmann::json json;
            /* std::string signature_base64 = Base64::encode(request.client_signature.data(), request.client_signature.size()); */
            json["client_id_num"] = body.client_id_num;
            json["timestamp"] = body.timestamp;
            json["last_name"] = body.last_name;
            json["first_name"] = body.first_name;
            json["middle_name"] = body.middle_name;
            json["voter_unique_id"] = body.voter_unique_id;
            json["verified_id_message"] = VerifiedVoterID::ToJson(body.verified_id_message);
            /* json["client_signature"] = signature_base64; */
            return json;
        }
    };

    Body body;

    /**
     * A signature on this message using the client's public key.
     */
    std::vector<std::uint8_t> client_signature;

    CheckinRequest(const Body& message_body,
                   const std::vector<std::uint8_t>& client_signature)
            : body(message_body),
              client_signature(client_signature) {}

    /* DEFAULT_SERIALIZATION_SUPPORT(CheckinRequest, body, client_signature); */
    static nlohmann::json ToJson(const CheckinRequest& request) {
        nlohmann::json json;
        json["body"] = CheckinRequest::Body::ToJson(request.body);
        std::string signature_base64 = Base64::encode(request.client_signature.data(), request.client_signature.size());
        json["client_signature"] = signature_base64;
        return json;
    }

    static CheckinRequest FromJson(const nlohmann::json& json) {
        CheckinRequest::Body request_body(
                json["body"]["client_id_num"],
                json["body"]["timestamp"],
                json["body"]["last_name"],
                json["body"]["first_name"],
                json["body"]["middle_name"],
                json["body"]["voter_unique_id"],
                VerifiedVoterID::FromJson(json["body"]["verified_id_message"]));

        std::vector<std::uint8_t> client_signature = Base64::decode(json["client_signature"]);
        CheckinRequest request(std::move(request_body), client_signature);

        return request;
    }
};

/**
 * A message from the Check-in Service sent in response to a CheckinRequest message.
 */
struct CheckinResponse {
    struct Body {
        /**
         * True if the check-in request was approved, false if it was denied.
         */
        bool approved;
        /**
         * The unique ID number of the client device that made the request. If the
         * request was approved, it means that the voter can check in at this
         * particular device.
         */
        std::uint32_t requesting_client_id;
        /**
         * The time, as a system-clock timestamp in milliseconds, when the server
         * sent this response.
         */
        std::uint64_t timestamp;
        /** The voter's last name */
        std::string last_name;
        /** The voter's first name */
        std::string first_name;
        /** The voter's middle name */
        std::string middle_name;
        /**
         * The unique ID number identifying this voter within the pollbook system, as
         * agreed upon by the pollbook system and the voter ID service.
         */
        std::uint32_t voter_unique_id;
        Body(bool approved,
             std::uint32_t requesting_client_id,
             std::uint64_t timestamp,
             const std::string& last_name,
             const std::string& first_name,
             const std::string& middle_name,
             std::uint32_t voter_unique_id)
                : approved(approved),
                  requesting_client_id(requesting_client_id),
                  timestamp(timestamp),
                  last_name(last_name),
                  first_name(first_name),
                  middle_name(middle_name),
                  voter_unique_id(voter_unique_id) {}
        /* DEFAULT_SERIALIZATION_SUPPORT(Body, approved, requesting_client_id, timestamp, last_name, first_name, middle_name, voter_unique_id); */

        static nlohmann::json ToJson(const CheckinResponse::Body& body) {
            nlohmann::json json;
            /* std::string signature_base64 = Base64::encode(response.checkin_service_signature.data(), response.checkin_service_signature.size()); */
            json["approved"] = body.approved;
            json["requesting_client_id"] = body.requesting_client_id;
            json["timestamp"] = body.timestamp;
            json["last_name"] = body.last_name;
            json["first_name"] = body.first_name;
            json["middle_name"] = body.middle_name;
            json["voter_unique_id"] = body.voter_unique_id;

            return json;
        }
    };
    Body body;
    /**
     * A signature on this message using the check-in service's public key.
     */
    std::vector<std::uint8_t> checkin_service_signature;
    /**
     * Randomly generated nonce that is sent after validation 
     */
    std::string ticket;

    CheckinResponse(const Body& message_body,
                    const std::vector<std::uint8_t>& checkin_service_signature,
                    const std::string& client_ticket)
            : body(message_body),
              checkin_service_signature(checkin_service_signature),
              ticket(client_ticket) {}

    // Functions to convert json to a response and vice versa
    static nlohmann::json ToJson(const CheckinResponse& response) {
        nlohmann::json json;
        std::string signature_base64 = Base64::encode(response.checkin_service_signature.data(), response.checkin_service_signature.size());
        json["body"] = CheckinResponse::Body::ToJson(response.body);
        json["checkin_service_signature"] = signature_base64;
        json["ticket"] = response.ticket;
        return json;
    }

    static CheckinResponse FromJson(const nlohmann::json& json) {
        CheckinResponse::Body response_body(
                json["body"]["approved"],
                json["body"]["requesting_client_id"],
                json["body"]["timestamp"],
                json["body"]["last_name"],
                json["body"]["first_name"],
                json["body"]["middle_name"],
                json["body"]["voter_unique_id"]);

        std::vector<std::uint8_t> service_signature = Base64::decode(json["checkin_service_signature"]);
        CheckinResponse response(std::move(response_body), service_signature, json["ticket"]);

        return response;
    }
};

}  // namespace epollbook
