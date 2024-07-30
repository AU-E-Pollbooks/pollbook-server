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
    // std::uint32_t client_id;
    std::uint32_t voter_unique_id;
    std::string ticket;

    TicketRequest(std::uint32_t voter_unique_id,
                   std::string ticket)
            : voter_unique_id(voter_unique_id),
              ticket(ticket) {}

    static nlohmann::json ToJson(const TicketRequest& request) {
        nlohmann::json json;
        json["voter_unique_id"] = request.voter_unique_id;
        json["ticket"] = request.ticket;
        return json;
    }

    static TicketRequest FromJson(const nlohmann::json& json) {
        TicketRequest request(
            json["voter_unique_id"],
            json["ticket"]
        );
        return request;
    }
};

/**
 * A message from the Check-in Service sent in response to a CheckinRequest message.
 */
struct TicketResponse {
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
    std::string secret;

    TicketResponse(bool approved,
            const std::string& last_name,
            const std::string& first_name,
            const std::string& middle_name,
            std::uint32_t voter_unique_id,
            std::string secret)
            : approved(approved),
              last_name(last_name),
              first_name(first_name),
              middle_name(middle_name),
              voter_unique_id(voter_unique_id),
              secret(secret) {}

    static nlohmann::json ToJson(const TicketResponse& response) {
        nlohmann::json json;
        /* std::string signature_base64 = Base64::encode(response.checkin_service_signature.data(), response.checkin_service_signature.size()); */
        json["approved"] = response.approved;
        json["last_name"] = response.last_name;
        json["first_name"] = response.first_name;
        json["middle_name"] = response.middle_name;
        json["voter_unique_id"] = response.voter_unique_id;
        json["secret"] = response.secret;

        return json;
    }

    // CheckinResponse(const Body& message_body,
    //                 const std::vector<std::uint8_t>& checkin_service_signature,
    //                 const std::string& client_ticket)
    //         : body(message_body),
    //           checkin_service_signature(checkin_service_signature),
    //           ticket(client_ticket) {}

    // Functions to convert json to a response and vice versa

    static TicketResponse FromJson(const nlohmann::json& json) {
        TicketResponse response (
                json["approved"],
                json["last_name"],
                json["first_name"],
                json["middle_name"],
                json["voter_unique_id"],
                json["secret"]);


        return response;
    }
};

}  // namespace epollbook

