#include "epollbook/voter_id_service.hpp"
#include "epollbook/config/config.hpp"
#include "epollbook/log_utils.hpp"

#include <spdlog/fmt/ostr.h>
#include <asio.hpp>

#include <array>
#include <chrono>
#include <cmath>
#include <iostream>

namespace epollbook {

VoterIDService::VoterIDService()
    : logger(spdlog::get(LogUtils::get_default_logger_name())),
      connection_listener(network_io_context,
                          asio::ip::tcp::endpoint(asio::ip::tcp::tcp::v4(),
                                                  Config::getUInt16(Config::SECTION_BASIC, Config::ID_SERVICE_PORT))),
      signer(openssl::EnvelopeKey::from_pem_private(Config::getString(Config::SECTION_SECURITY, Config::LOCAL_PRIVATE_KEY)),
             signature_digest_algorithm) {}

void VoterIDService::do_accept() {
    connection_listener.async_accept(network_io_context,
                                     [this](const asio::error_code& error, asio::ip::tcp::socket peer) {
                                         handle_accept(error, std::move(peer));
                                     });
}

void VoterIDService::handle_accept(const asio::error_code& error, asio::ip::tcp::socket new_socket) {
    asio::ip::tcp::endpoint client_ip = new_socket.remote_endpoint();
    logger->debug("Accepted a connection from client at {}", client_ip);
    // Put the new socket in the map
    client_sockets.emplace(client_ip, std::move(new_socket));
    // Start a read for the message size
    start_size_read(client_ip);
    // Enqueue another accept operation for the connection listener so it keeps listening
    do_accept();
}

void VoterIDService::start_size_read(asio::ip::tcp::endpoint client_ip) {
    std::shared_ptr<std::size_t> message_size = std::make_shared<std::size_t>();
    asio::async_read(client_sockets.at(client_ip),
                     asio::buffer(&(*message_size), sizeof(std::size_t)),
                     [this, client_ip, message_size](const asio::error_code& error, std::size_t bytes_read) {
                         if(!error) {
                             logger->debug("Client at {}: Message size is {} bytes", client_ip, *message_size);
                             start_payload_read(client_ip, *message_size);
                         } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
                             logger->debug("Client at {} disconnected before sending message size", client_ip);
                             client_sockets.erase(client_ip);
                         } else {
                             logger->warn("Unexpected I/O error when reading a request message from client {}. Error: {}", client_ip, error.message());
                         }
                     });
}

void VoterIDService::start_payload_read(const asio::ip::tcp::endpoint& client_ip, std::size_t size_of_message) {
    client_receive_buffers.emplace(client_ip, std::vector<uint8_t>(size_of_message));
    asio::async_read(client_sockets.at(client_ip),
                     asio::buffer(client_receive_buffers.at(client_ip)),
                     [this, client_ip](const asio::error_code& error, std::size_t bytes_transferred) {
                         if(!error) {
                             // We shouldn't have to check bytes_transferred because async_read was called in "read all" mode
                             assert(bytes_transferred == client_receive_buffers.at(client_ip).size());
                             logger->debug("Finished reading message of size {} from client at {}", client_receive_buffers.at(client_ip).size(), client_ip);
                             // There's only one type of message the client could send, so deserialize and handle it
                             auto request = mutils::from_bytes<VoterIDRequest>(nullptr, client_receive_buffers.at(client_ip).data());
                             handle_validation_request(client_ip, *request);
                         } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
                             logger->debug("Client at {} disconnected before sending entire message", client_ip);
                             client_sockets.erase(client_ip);
                         } else {
                             logger->warn("Unexpected I/O error when reading a request message from client {}. Error: {}", client_ip, error.message());
                         }
                     });
}

void VoterIDService::handle_validation_request(const asio::ip::tcp::endpoint& client_ip, const VoterIDRequest& request) {
    auto current_time = std::chrono::system_clock::now();
    uint64_t current_timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     current_time.time_since_epoch())
                                     .count();
    // Attempt to safely subtract two unsigned values without knowing which is bigger
    int64_t time_difference = current_timestamp > request.body.timestamp
                                  ? current_timestamp - request.body.timestamp
                                  : request.body.timestamp - current_timestamp;
    if(std::abs(time_difference) > Config::getUInt32(Config::SECTION_SECURITY, Config::REQUEST_FRESHNESS_INTERVAL)) {
        logger->warn("Rejected a voter ID validation request for being stale. Request timestamp was {} ms in the past", time_difference);
        return;
    }
    if(!validate_id_data(request.body.voter_id_data)) {
        logger->warn("Rejected a voter ID validation request because the ID data was not valid.");
        return;
    }
    // Ensure the public key for this client is in memory
    if(client_verifiers.find(request.body.client_id_num) == client_verifiers.end()) {
        if(!load_client_public_key(request.body.client_id_num)) {
            logger->warn("Could not load the public key for client number {}. Ignoring a voter ID validation request.", request.body.client_id_num);
            return;
        }
    }
    // Validate the client's signature
    std::vector<std::uint8_t> request_body_bytes(mutils::bytes_size(request.body));
    mutils::to_bytes(request.body, request_body_bytes.data());
    openssl::Verifier& verifier = client_verifiers.at(request.body.client_id_num);
    verifier.init();
    verifier.add_bytes(request_body_bytes.data(), request_body_bytes.size());
    if(!verifier.finalize(request.client_signature)) {
        logger->warn("Rejected a voter ID validation request because the client's signature was invalid.");
        return;
    }
    logger->info("Approved a voter ID validation request from client #{} at {}", request.body.client_id_num, client_ip);

    // Sign the validation request to assert that it is valid
    // The request was already serialized, in the receive buffer, so there's no need to serialize it again
    const std::vector<std::uint8_t>& request_bytes = client_receive_buffers.at(client_ip);
    signer.init();
    signer.add_bytes(request_bytes.data(), request_bytes.size());
    std::vector<std::uint8_t> signature = signer.finalize();

    // Send it back in a response. For now, the write is synchronous, since we don't expect it to take very long.
    VerifiedVoterID response(request, std::move(signature));
    std::size_t response_size = mutils::bytes_size(response);
    std::vector<uint8_t> response_bytes(response_size + sizeof(response_size));
    mutils::to_bytes(response_size, response_bytes.data());
    mutils::to_bytes(response, response_bytes.data() + sizeof(response_size));
    logger->debug("Sending a response of size {} to client at {}", response_size, client_ip);
    asio::write(client_sockets.at(client_ip), asio::buffer(response_bytes));
}

bool VoterIDService::validate_id_data(const std::vector<std::uint8_t>& id_data) {
    return true;
}

bool VoterIDService::load_client_public_key(std::uint32_t client_id) {
    std::stringstream key_file_path_builder;
    key_file_path_builder << Config::getString(Config::SECTION_SECURITY, Config::CLIENT_KEYS_FOLDER) << "/"
                          << Config::getString(Config::SECTION_SECURITY, Config::CLIENT_KEY_FILE_PREFIX) << client_id << ".pem";
    std::string key_file_path = key_file_path_builder.str();
    try {
        openssl::Verifier client_verifier(openssl::EnvelopeKey::from_pem_public(key_file_path), signature_digest_algorithm);
        client_verifiers.emplace(client_id, std::move(client_verifier));
        logger->debug("Loaded public key for client #{} from file {}", client_id, key_file_path);
    } catch(openssl::openssl_error& err) {
        logger->error("Could not load public key for client {} from file {}. OpenSSL error: {}", client_id, key_file_path, err.what());
        return false;
    }
    return true;
}

void VoterIDService::run() {
    // Post the first asynchronous accept
    do_accept();
    network_io_context.run();
}

}  // namespace epollbook
