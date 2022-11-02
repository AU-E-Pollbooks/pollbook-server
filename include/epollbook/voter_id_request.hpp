#pragma once

#include "mutils-serialization/SerializationSupport.hpp"

#include <cstdint>
#include <vector>

namespace epollbook {

/**
 * A message to be sent over the network from a pollbook client to the Voter ID
 * service when it requests verification of a voter's ID.
 */
struct VoterIDRequest : public mutils::ByteRepresentable {
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
        /**
         * A binary data blob representing the voter's physical ID. This could be
         * an image, a barcode, or some other application-defined data format.
         */
        std::vector<std::uint8_t> voter_id_data;
        Body(std::uint32_t client_id_num,
             std::uint64_t timestamp,
             const std::vector<std::uint8_t>& voter_id_data)
            : client_id_num(client_id_num),
              timestamp(timestamp),
              voter_id_data(voter_id_data) {}

        DEFAULT_SERIALIZATION_SUPPORT(Body, client_id_num, timestamp, voter_id_data);
    };

    Body body;

    /**
     * A signature on this message using the client's public key
     */
    std::vector<std::uint8_t> client_signature;

    VoterIDRequest(const Body& message_body,
                   const std::vector<std::uint8_t>& client_signature)
        : body(message_body),
          client_signature(client_signature) {}

    DEFAULT_SERIALIZATION_SUPPORT(VoterIDRequest, body, client_signature);
};

/**
 * A message from the Voter ID service sent in response to a voter ID request.
 * Contains a copy of the VoterIDRequest message plus a signature on it
 * from the ID service, which attests that the service has verified this ID.
 */
struct VerifiedVoterID : public mutils::ByteRepresentable {
    /**
     * The voter ID presented by a client, i.e. the voter ID data together
     * with the client's ID, timestamp, and signature. This is just a copy
     * of the entire VoterIDRequest message that the service received.
     */
    VoterIDRequest presented_id;
    /**
     * A signature on the entire message, including the client's signature, using
     * the ID service's public key.
     */
    std::vector<std::uint8_t> id_service_signature;
    VerifiedVoterID(const VoterIDRequest& id_request,
                    const std::vector<std::uint8_t>& id_service_signature)
        : presented_id(id_request),
          id_service_signature(id_service_signature) {}

    DEFAULT_SERIALIZATION_SUPPORT(VerifiedVoterID, presented_id, id_service_signature);
};

}  // namespace epollbook