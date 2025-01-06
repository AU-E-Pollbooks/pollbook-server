#pragma once

#include "voter_id_request.hpp"
#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>
#include "openssl/base64.hpp"


namespace epollbook {

/**
 * A message to be sent over the network from a pollbook client to the Check-in
 * Service when it makes a request to check in a particular voter.
 */
struct TicketRequest {
    /**
     * This inner struct defines the "body" fields of the request message,
     * which is everything except the signature. The outer struct contains
     * one Body instance and the signature.
     */
    struct Body {
        std::uint32_t client_id;
        std::uint32_t voter_unique_id;
        std::uint64_t timestamp;
        std::string ticket;
        std::uint32_t pin;

        Body(std::uint32_t client_id,
             std::uint32_t voter_unique_id,
             std::uint64_t timestamp,
             std::string ticket,
             std::uint32_t pin) 
            : client_id(client_id),
              voter_unique_id(voter_unique_id),
              timestamp(timestamp),
              // ticket(ticket),
              pin(pin){}

        static nlohmann::json ToJson(const TicketRequest::Body& body) {
            nlohmann::json json;
            json["client_id"] = body.client_id;
            json["voter_unique_id"] = body.voter_unique_id;
            json["timestamp"] = body.timestamp;
            // json["ticket"] = body.ticket;
            json["pin"] = body.pin;
            return json;
        }
    };

    Body body;
    /**
     * A signature on this message using the client's public key.
     */
    std::vector<std::uint8_t> signature;
    TicketRequest(const Body& message_body,
                  const std::vector<std::uint8_t>& signature)
            : body(message_body),
              signature(signature) {}

    static nlohmann::json ToJson(const TicketRequest& request) {
        nlohmann::json json;
        json["body"] = TicketRequest::Body::ToJson(request.body);
        std::string signature_base64 = Base64::encode(request.signature.data(), request.signature.size());
        json["signature"] = signature_base64;
        return json;
    }
    static TicketRequest FromJson(const nlohmann::json& json) {
        if (!json.contains("body") || !json.contains("signature")) {
            throw std::runtime_error("Missing 'body' or 'signature' in JSON");
        }
        const auto& body = json["body"];
        if (!body.is_object() ||
            !body.contains("client_id") ||
            !body.contains("voter_unique_id") ||
            !body.contains("timestamp") ||
            !body.contains("ticket") ||
            !body.contains("pin")) {
            throw std::runtime_error("Invalid or incomplete 'body' structure in JSON");
        }
        TicketRequest::Body request_body(
            json["body"]["client_id"],
            json["body"]["voter_unique_id"],
            json["body"]["timestamp"],
            json["body"]["ticket"],
            json["body"]["pin"]
        );
        std::vector<std::uint8_t> signature = Base64::decode(json["signature"]);

        TicketRequest request(std::move(request_body), signature);
        return request;
    }
};

/**
 * A message from the Check-in Service sent in response to a CheckinRequest message.
 */
struct TicketResponse {
    struct Body {
        /**
        * True if the check-in request was approved, false if it was denied.
        */
        bool approved;
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
        std::uint32_t pin;
        std::string secret;

        Body(bool approved,
             const std::string& last_name,
             const std::string& first_name,
             const std::string& middle_name,
             std::uint32_t voter_unique_id,
             std::uint32_t pin,
             std::string secret)
            : approved(approved),
              last_name(last_name),
              first_name(first_name),
              middle_name(middle_name),
              voter_unique_id(voter_unique_id),
              pin(pin),
              secret(secret) {}

        static nlohmann::json ToJson(const TicketResponse::Body& response) {
            nlohmann::json json;
            /* std::string signature_base64 = Base64::encode(response.checkin_service_signature.data(), response.checkin_service_signature.size()); */
            json["approved"] = response.approved;
            json["last_name"] = response.last_name;
            json["first_name"] = response.first_name;
            json["middle_name"] = response.middle_name;
            json["voter_unique_id"] = response.voter_unique_id;
            json["pin"] = response.pin;
            json["secret"] = response.secret;

            return json;
        }

    };
    Body body;
    TicketResponse(const Body& message_body,
                  const std::vector<std::uint8_t>& signature)
            : body(message_body),
              signature(signature) {}
    std::vector<std::uint8_t> signature;
    static nlohmann::json ToJson(const TicketResponse& response) {
        nlohmann::json json;
        std::string signature_base64 = Base64::encode(response.signature.data(), response.signature.size());
        json["body"] = TicketResponse::Body::ToJson(response.body);
        json["signature"] = signature_base64;

        return json;
    }

    static TicketResponse FromJson(const nlohmann::json& json) {
        // TicketResponse::Body response_body = TicketResponse::Body::FromJson(json);
        TicketResponse::Body response_body (
            json["body"]["approved"],
            json["body"]["last_name"],
            json["body"]["first_name"],
            json["body"]["middle_name"],
            json["body"]["voter_unique_id"],
            json["body"]["pin"],
            json["body"]["secret"]
        );
        std::vector<std::uint8_t> signature = Base64::decode(json["signature"]);
        TicketResponse response(response_body, signature);
        return response;
    }
};

}  // namespace epollbook

