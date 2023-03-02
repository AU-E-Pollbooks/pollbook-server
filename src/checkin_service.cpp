#include "epollbook/checkin_service.hpp"
#include "epollbook/config/config.hpp"
#include "epollbook/log_utils.hpp"

#include <asio.hpp>

#include <array>
#include <iostream>

namespace epollbook {

CheckinService::CheckinService()
    : logger(spdlog::get(LogUtils::get_default_logger_name())),
      connection_listener(network_io_context,
                          asio::ip::tcp::endpoint(
                              asio::ip::tcp::tcp::v4(),
                              Config::getUInt16(Config::SECTION_BASIC, Config::CHECKIN_SERVICE_PORT))),
      id_service_verifier(openssl::EnvelopeKey::from_pem_public(
                              Config::getString(Config::SECTION_SECURITY, Config::ID_SERVICE_PUBLIC_KEY)),
                          openssl::DigestAlgorithm::SHA256),
      signer(openssl::EnvelopeKey::from_pem_private(Config::getString(Config::SECTION_SECURITY, Config::LOCAL_PRIVATE_KEY)),
             signature_digest_algorithm) {
    load_voter_list(Config::getString(Config::SECTION_BASIC, Config::VOTER_LIST_FILE));
}

void CheckinService::do_accept() {
    connection_listener.async_accept(network_io_context,
                                     [this](const asio::error_code& error, asio::ip::tcp::socket peer) {
                                         handle_accept(error, std::move(peer));
                                     });
}

void CheckinService::handle_accept(const asio::error_code& error, asio::ip::tcp::socket new_socket) {
    asio::ip::tcp::endpoint client_ip = new_socket.remote_endpoint();
    logger->debug("Accepted a connection from client at {}", client_ip);
    // Put the new socket in the map
    client_sockets.emplace(client_ip, std::move(new_socket));
    // Start a read for the message size
    start_size_read(client_ip);
    // Enqueue another accept operation for the connection listener so it keeps listening
    do_accept();
}

void CheckinService::start_size_read(asio::ip::tcp::endpoint client_ip) {
    // Put this integer on the heap so it stays in memory after this method ends
    std::shared_ptr<std::size_t> message_size = std::make_shared<std::size_t>();
    // Make an asio "buffer" that points to the address of the integer and read 4 bytes into it
    asio::async_read(client_sockets.at(client_ip),
                     asio::buffer(&(*message_size), sizeof(std::size_t)),
                     [this, client_ip, message_size](const asio::error_code& error, std::size_t bytes_read) {
                         if(!error) {
                             logger->debug("Client at {}: Message size is {} bytes", client_ip, *message_size);
                             start_payload_read(client_ip, *message_size);
                         } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
                             logger->debug("Client at {} disconnected before sending message size", client_ip);
                             client_sockets.erase(client_ip);
                         }
                     });
}

void CheckinService::start_payload_read(const asio::ip::tcp::endpoint& client_ip, std::size_t size_of_message) {
    // Allocate a buffer for the message
    client_receive_buffers.emplace(client_ip, std::vector<uint8_t>(size_of_message));
    // Asynchronously read until it is full
    asio::async_read(client_sockets.at(client_ip),
                     asio::buffer(client_receive_buffers.at(client_ip)),
                     [this, client_ip](const asio::error_code& error, std::size_t bytes_transferred) {
                         if(!error) {
                             assert(bytes_transferred == client_receive_buffers.at(client_ip).size());
                             logger->debug("Finished reading message of size {} from client at {}", client_receive_buffers.at(client_ip).size(), client_ip);
                             // There's only one type of message the client could send, so deserialize and handle it
                             auto request = mutils::from_bytes<CheckinRequest>(nullptr, client_receive_buffers.at(client_ip).data());
                             handle_checkin_request(client_ip, *request);
                         } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
                             logger->debug("Client at {} disconnected before sending entire message", client_ip);
                             client_sockets.erase(client_ip);
                         } else {
                             logger->warn("Unexpected I/O error when reading a request message from client {}. Error: {}", client_ip, error.message());
                         }
                     });
}

void CheckinService::handle_checkin_request(const asio::ip::tcp::endpoint& client_ip, const CheckinRequest& request) {
    // Ensure the public key for this client is in memory
    if(client_verifiers.find(request.body.client_id_num) == client_verifiers.end()) {
        if(!load_client_public_key(request.body.client_id_num)) {
            logger->warn("Could not load the public key for client number {}. Ignoring a voter ID validation request.", request.body.client_id_num);
            return;
        }
    }
    auto current_time = std::chrono::system_clock::now();
    uint64_t current_timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     current_time.time_since_epoch())
                                     .count();
    bool accept = false;
    if(validate_client_request(request, current_timestamp)) {
        auto find_voter_result = voter_status_table.find(request.body.voter_unique_id);
        if(find_voter_result != voter_status_table.end()) {
            if(find_voter_result->second == VoterStatus::ELIGIBLE) {
                find_voter_result->second = VoterStatus::CHECKED_IN;
                logger->debug("Accepted a check-in request for voter {} {} {} (UID {}) from client {}", request.body.first_name, request.body.middle_name, request.body.last_name, request.body.voter_unique_id, request.body.client_id_num);
                accept = true;
            } else {
                logger->debug("Rejecting client {}'s check-in request for {} {} {} (UID {}) because the voter has already checked in",
                              request.body.client_id_num, request.body.first_name, request.body.middle_name, request.body.last_name, request.body.voter_unique_id);
            }
        }
    }

    CheckinResponse::Body response_body(accept, request.body.client_id_num,
                                        current_timestamp, request.body.last_name, request.body.first_name,
                                        request.body.middle_name, request.body.voter_unique_id);
    // Sign the body of the response message with the service's key
    std::vector<std::uint8_t> response_body_bytes(mutils::bytes_size(response_body));
    mutils::to_bytes(response_body, response_body_bytes.data());
    signer.init();
    signer.add_bytes(response_body_bytes.data(), response_body_bytes.size());
    // Serialize and send the response message, including the signature
    CheckinResponse response(std::move(response_body), signer.finalize());
    std::size_t response_size = mutils::bytes_size(response);
    std::vector<uint8_t> response_bytes(response_size + sizeof(response_size));
    mutils::to_bytes(response_size, response_bytes.data());
    mutils::to_bytes(response, response_bytes.data() + sizeof(response_size));
    logger->debug("Sending a response of size {} to client at {}", response_size, client_ip);
    asio::write(client_sockets.at(client_ip), asio::buffer(response_bytes));
    // Enqueue another read operation for the next message from this client (if any)
    start_size_read(client_ip);
}

bool CheckinService::validate_client_request(const CheckinRequest& request, std::uint64_t current_timestamp) {
    // Verify the client's signature on the message
    std::vector<std::uint8_t> request_body_bytes(mutils::bytes_size(request.body));
    mutils::to_bytes(request.body, request_body_bytes.data());
    openssl::Verifier& verifier = client_verifiers.at(request.body.client_id_num);
    verifier.init();
    verifier.add_bytes(request_body_bytes.data(), request_body_bytes.size());
    if(!verifier.finalize(request.client_signature)) {
        logger->debug("Rejecting client {}'s check-in request for {} {} {} (UID {}) because the client's signature on the message was invalid",
                      request.body.client_id_num, request.body.first_name, request.body.middle_name, request.body.last_name, request.body.voter_unique_id);
        return false;
    }
    // If the client's signature was valid, verify the ID service's signature
    std::size_t id_request_size = mutils::bytes_size(request.body.verified_id_message.presented_id);
    std::size_t voter_uid_size = mutils::bytes_size(request.body.verified_id_message.voter_unique_id);
    std::vector<std::uint8_t> id_message_bytes(id_request_size + voter_uid_size);
    mutils::to_bytes(request.body.verified_id_message.presented_id, id_message_bytes.data());
    mutils::to_bytes(request.body.verified_id_message.voter_unique_id, id_message_bytes.data() + id_request_size);
    id_service_verifier.init();
    id_service_verifier.add_bytes(id_message_bytes.data(), id_message_bytes.size());
    if(!id_service_verifier.finalize(request.body.verified_id_message.id_service_signature)) {
        logger->debug("Rejecting client {}'s check-in request for {} {} {} (UID {}) because the signature on the ID verification was invalid",
                      request.body.client_id_num, request.body.first_name, request.body.middle_name, request.body.last_name, request.body.voter_unique_id);
        return false;
    }
    // If the ID service's signature was valid, check the timestamp
    int64_t time_difference = current_timestamp > request.body.timestamp
                                  ? current_timestamp - request.body.timestamp
                                  : request.body.timestamp - current_timestamp;
    if(std::abs(time_difference) > Config::getUInt32(Config::SECTION_SECURITY, Config::REQUEST_FRESHNESS_INTERVAL)) {
        logger->debug("Rejecting client {}'s check-in request for {} {} {} (UID {}) because its timestamp, {}, was older than {} ms",
                      request.body.client_id_num, request.body.first_name, request.body.middle_name, request.body.last_name,
                      request.body.voter_unique_id, request.body.timestamp, Config::getUInt32(Config::SECTION_SECURITY, Config::REQUEST_FRESHNESS_INTERVAL));
        return false;
    }
    // At this point the request looks good, now we can actually attempt to check in the voter
    return true;
}

void CheckinService::run() {
    // Post the first asynchronous accept
    do_accept();
    logger->info("Check-in service started on port {}", Config::getUInt16(Config::SECTION_BASIC, Config::CHECKIN_SERVICE_PORT));
    network_io_context.run();
}

bool CheckinService::load_client_public_key(std::uint32_t client_id) {
    std::stringstream key_file_path_builder;
    key_file_path_builder << Config::getString(Config::SECTION_SECURITY, Config::CLIENT_KEYS_FOLDER) << "/"
                          << Config::getString(Config::SECTION_SECURITY, Config::CLIENT_KEY_FILE_PREFIX) << client_id << ".pem";
    std::string key_file_path = key_file_path_builder.str();
    try {
        openssl::Verifier client_verifier(openssl::EnvelopeKey::from_pem_public(key_file_path), signature_digest_algorithm);
        client_verifiers.emplace(client_id, std::move(client_verifier));
    } catch(openssl::openssl_error& err) {
        logger->error("Could not load public key for client {} from file {}. OpenSSL error: {}", client_id, key_file_path, err.what());
        return false;
    }
    return true;
}

void CheckinService::load_voter_list(const std::string& csv_file_path) {
    std::ifstream csv_file_stream(csv_file_path);
    // First read the CSV header line
    std::string header_line;
    std::getline(csv_file_stream, header_line);
    // Ensure the expected headers are there
    if(header_line.substr(0, header_line.find(",")) != "UID") {
        throw std::runtime_error("Voter CSV file " + csv_file_path + " did not have the expected column headers");
    }
    std::string file_line;
    while(std::getline(csv_file_stream, file_line)) {
        // For now, just get the first column (the UID) and ignore the others
        // If we need to load more information I'll write a real CSV parser
        std::string uid_column_string = file_line.substr(0, file_line.find(","));
        std::uint32_t uid = std::stoul(uid_column_string);
        voter_status_table.emplace(uid, VoterStatus::ELIGIBLE);
    }
}

}  // namespace epollbook
