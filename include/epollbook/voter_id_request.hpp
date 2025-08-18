#pragma once

#include "openssl/base64.hpp"
#include <nlohmann/json.hpp>

#include <cstdint>
#include <vector>

namespace epollbook {

/**
 * A message to be sent over the network from a pollbook client to the Voter ID
 * service when it requests verification of a voter's ID.
 */
struct VoterIDRequest {
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
        std::string last_name;
        std::string middle_name;
        std::string first_name;
        /**
         * A binary data blob representing the voter's physical ID. This could be
         * an image, a barcode, or some other application-defined data format.
         */
        std::vector<std::uint8_t> voter_id_data;
        Body(std::uint32_t client_id_num,
             std::uint64_t timestamp,
             std::string last_name,
             std::string middle_name,
             std::string first_name,
             const std::vector<std::uint8_t>& voter_id_data)
                : client_id_num(client_id_num),
                  timestamp(timestamp),
                  last_name(last_name),
                  middle_name(middle_name),
                  first_name(first_name),
                  voter_id_data(voter_id_data) {}

        static nlohmann::json ToJson(const VoterIDRequest::Body& body) {
            nlohmann::json json;
            std::string voter_id_str = Base64::encode(body.voter_id_data.data(), body.voter_id_data.size());
            json["client_id_num"] = body.client_id_num;
            json["timestamp"] = body.timestamp;
            json["last_name"] = body.last_name;
            json["middle_name"] = body.middle_name;
            json["first_name"] = body.first_name;
            json["voter_id_data"] = voter_id_str;
            return json;
        } 
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

    static nlohmann::json ToJson(const VoterIDRequest& request) {
        nlohmann::json json;
        std::string signature_base64 = Base64::encode(request.client_signature.data(), request.client_signature.size());
        json["body"] = VoterIDRequest::Body::ToJson(request.body);
        json["client_signature"] = signature_base64;
        return json;
    } 

    static VoterIDRequest FromJson(const nlohmann::json& json) {
        std::vector<uint8_t> voter_id = Base64::decode(json["body"]["voter_id_data"]);
        VoterIDRequest::Body request_body(
                json["body"]["client_id_num"],
                json["body"]["timestamp"],
                json["body"]["last_name"],
                json["body"]["middle_name"],
                json["body"]["first_name"],
                voter_id); 
        

        std::vector<std::uint8_t> client_signature = Base64::decode(json["client_signature"]);

        VoterIDRequest request(std::move(request_body), client_signature);

        return request;
    }
};

/**
 * A message from the Voter ID service sent in response to a voter ID request.
 * Contains a copy of the VoterIDRequest message, the unique ID number of the
 * voter that this ID document corresponds to, and a signature on everything
 * from the ID service, which attests that the service has verified the ID
 * document and matched it to a specific voter known to the pollbook system.
 */
struct VerifiedVoterID {
    /**
     * The voter ID presented by a client, i.e. the voter ID data together
     * with the client's ID, timestamp, and signature. This is just a copy
     * of the entire VoterIDRequest message that the service received.
     */
    VoterIDRequest presented_id;
    /**
     * A unique ID number identifying this voter within the pollbook system.
     * Voter unique IDs should be pre-agreed-upon by the pollbook system and
     * the ID-verification system, so that the ID-verification system can
     * clearly match identification documents with specific voters in the
     * pollbook's registered voters database.
     */
    std::uint32_t voter_unique_id;
    /**
     * A signature on the entire message, including the client's signature, using
     * the ID service's public key.
     */
    std::vector<std::uint8_t> id_service_signature;
    VerifiedVoterID(const VoterIDRequest& id_request,
                    std::uint32_t voter_uid,
                    const std::vector<std::uint8_t>& id_service_signature)
            : presented_id(id_request),
              voter_unique_id(voter_uid),
              id_service_signature(id_service_signature) {}

    static nlohmann::json ToJson(const VerifiedVoterID& ID) {
        nlohmann::json json;
        std::string signature_base64 = Base64::encode(ID.id_service_signature.data(), ID.id_service_signature.size());
        json["presented_id"] = VoterIDRequest::ToJson(ID.presented_id);
        json["voter_unique_id"] = ID.voter_unique_id;
        json["id_service_signature"] = signature_base64;
        return json;
    }

    static VerifiedVoterID FromJson(const nlohmann::json& json) {
        VoterIDRequest presented_id = VoterIDRequest::FromJson(json["presented_id"]);
        std::uint32_t voter_unique_id = json["voter_unique_id"];
        std::vector<std::uint8_t> id_service_signature = Base64::decode(json["id_service_signature"]);
        return VerifiedVoterID(presented_id, voter_unique_id, id_service_signature);
    }
};

}  // namespace epollbook
