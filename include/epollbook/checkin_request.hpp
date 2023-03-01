#pragma once

#include "mutils-serialization/SerializationSupport.hpp"
#include "voter_id_request.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace epollbook {

/**
 * A message to be sent over the network from a pollbook client to the Check-in
 * Service when it makes a request to check in a particular voter.
 */
struct CheckinRequest : public mutils::ByteRepresentable {
    /**
     * This inner struct defines the "body" fields of the request message,
     * which is everything except the signature. The outer struct contains
     * one Body instance and the signature.
     */
    struct Body : public mutils::ByteRepresentable {
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
        DEFAULT_SERIALIZATION_SUPPORT(Body, client_id_num, timestamp, last_name, first_name, middle_name, voter_unique_id, verified_id_message);
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

    DEFAULT_SERIALIZATION_SUPPORT(CheckinRequest, body, client_signature);
};

/**
 * A message from the Check-in Service sent in response to a CheckinRequest message.
 */
struct CheckinResponse : public mutils::ByteRepresentable {
    struct Body : public mutils::ByteRepresentable {
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
        DEFAULT_SERIALIZATION_SUPPORT(Body, approved, requesting_client_id, timestamp, last_name, first_name, middle_name, voter_unique_id);
    };
    Body body;
    /**
     * A signature on this message using the check-in service's public key.
     */
    std::vector<std::uint8_t> checkin_service_signature;

    CheckinResponse(const Body& message_body,
                    const std::vector<std::uint8_t>& checkin_service_signature)
        : body(message_body),
          checkin_service_signature(checkin_service_signature) {}

    DEFAULT_SERIALIZATION_SUPPORT(CheckinResponse, body, checkin_service_signature);
};

}  // namespace epollbook
