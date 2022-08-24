#include "epollbook/voter_id_service.hpp"
#include "epollbook/log_utils.hpp"

#include <spdlog/fmt/ostr.h>
#include <asio.hpp>

#include <array>
#include <chrono>
#include <cmath>
#include <iostream>

namespace epollbook {

VoterIDService::VoterIDService(std::uint16_t port, const std::string& private_key_filename)
    : logger(spdlog::get(LogUtils::get_default_logger_name())),
      connection_listener(network_io_context, asio::ip::tcp::endpoint(asio::ip::tcp::tcp::v4(), port)),
      signer(openssl::EnvelopeKey::from_pem_private(private_key_filename),
             openssl::DigestAlgorithm::SHA256) {}

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
                             logger->debug("Client at {}: Message size is {} bytes", client_ip, message_size);
                             start_body_read(client_ip, *message_size);
                         } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
                             logger->debug("Client at {} disconnected before sending message size", client_ip);
                             client_sockets.erase(client_ip);
                         }
                     });
}

void VoterIDService::start_body_read(const asio::ip::tcp::endpoint& client_ip, std::size_t size_of_message) {
    client_receive_buffers.emplace(client_ip, std::vector<uint8_t>(size_of_message));
    asio::async_read(client_sockets.at(client_ip),
                     asio::buffer(client_receive_buffers.at(client_ip)),
                     [this, client_ip](const asio::error_code& error, std::size_t bytes_transferred) {
                         handle_read(client_ip, error, bytes_transferred);
                     });
}

void VoterIDService::handle_read(const asio::ip::tcp::endpoint& client_ip, const asio::error_code& error, std::size_t bytes_transferred) {
    if(!error) {
        // We shouldn't have to check bytes_transferred because async_read was called in "read all" mode
        assert(bytes_transferred == client_receive_buffers.at(client_ip).size());
        logger->debug("Finished reading message of size {} from client at {}", client_receive_buffers.at(client_ip).size(), client_ip);
        // There's only one type of message the client could send, so deserialize and handle it
        auto request = mutils::from_bytes<VoterIDRequest>(nullptr, client_receive_buffers.at(client_ip).data());
        handle_validation_request(client_ip, *request);
    } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
        logger->debug("Client at {} disconnected before sending entire message", client_ip);
    }
}

void VoterIDService::handle_validation_request(const asio::ip::tcp::endpoint& client_ip, const VoterIDRequest& request) {
    auto current_time = std::chrono::system_clock::now();
    uint64_t current_timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     current_time.time_since_epoch())
                                     .count();
    // Attempt to safely subtract two unsigned values without knowing which is bigger
    int64_t time_difference = current_timestamp > request.timestamp
                                  ? current_timestamp - request.timestamp
                                  : request.timestamp - current_timestamp;
    if(std::abs(time_difference) > request_freshness_interval) {
        logger->warn("Rejected a voter ID validation request for being stale. Request timestamp was {} ms in the past", time_difference);
        return;
    }
    if(!validate_id_data(request.voter_id_data)) {
        logger->warn("Rejected a voter ID validation request because the ID data was not valid.");
        return;
    }
    // Validate the client's signature
    // This will require finding and loading a certificate for the client based on its IP address or hostname

    // Sign the validation request to assert that it is valid
    signer.init();
    signer.add_bytes(&request.timestamp, sizeof(request.timestamp));
    signer.add_bytes(request.voter_id_data.data(), request.voter_id_data.size());
    signer.add_bytes(request.client_signature.data(), request.client_signature.size());
    std::vector<std::uint8_t> signature = signer.finalize();

    // Send it back in a response. For now, the write is synchronous, since we don't expect it to take very long.
    VerifiedVoterID response(request.timestamp, request.voter_id_data, request.client_signature, std::move(signature));
    std::vector<uint8_t> response_bytes(mutils::bytes_size(response));
    mutils::to_bytes(response, response_bytes.data());
    asio::write(client_sockets.at(client_ip), asio::buffer(response_bytes));
}

bool VoterIDService::validate_id_data(const std::vector<std::uint8_t>& id_data) {
    return true;
}

void VoterIDService::run() {
    // Post the first asynchronous accept
    do_accept();
    network_io_context.run();
}

}  // namespace epollbook