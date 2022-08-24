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
    /**
     * A signature on this message using the client's public key
     */
    std::vector<std::uint8_t> client_signature;
    VoterIDRequest(std::uint64_t timestamp,
                   const std::vector<std::uint8_t>& voter_id_data,
                   const std::vector<std::uint8_t>& client_signature)
        : timestamp(timestamp),
          voter_id_data(voter_id_data),
          client_signature(client_signature) {}

    DEFAULT_SERIALIZATION_SUPPORT(VoterIDRequest, timestamp, voter_id_data, client_signature);
};

/**
 * A message from the Voter ID service sent in response to a voter ID request.
 * Contains the same fields as the VoterIDRequest message plus a signature
 * from the ID service, which attests that the service has verified this ID.
 */
struct VerifiedVoterID : public mutils::ByteRepresentable {
    std::uint64_t timestamp;
    std::vector<std::uint8_t> voter_id_data;
    std::vector<std::uint8_t> client_signature;
    std::vector<std::uint8_t> id_service_signature;
    VerifiedVoterID(std::uint64_t timestamp,
                    const std::vector<std::uint8_t>& voter_id_data,
                    const std::vector<std::uint8_t>& client_signature,
                    const std::vector<std::uint8_t>& id_service_signature)
        : timestamp(timestamp),
          voter_id_data(voter_id_data),
          client_signature(client_signature),
          id_service_signature(id_service_signature) {}

    DEFAULT_SERIALIZATION_SUPPORT(VerifiedVoterID, timestamp, voter_id_data, client_signature, id_service_signature);
};

}  // namespace epollbook