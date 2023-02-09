#include "epollbook/pollbook_client.hpp"
#include "epollbook/checkin_request.hpp"
#include "epollbook/config/config.hpp"
#include "epollbook/openssl/signature.hpp"
#include "epollbook/voter_id_request.hpp"

#include <asio.hpp>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace epollbook {

PollbookClient::PollbookClient()
    : logger(spdlog::get(LogUtils::get_default_logger_name())),
      network_work_guard(network_io_context.get_executor()),
      checkin_server_socket(network_io_context),
      id_server_socket(network_io_context),
      checkin_connected(false),
      id_connected(false),
      private_key_signer(openssl::EnvelopeKey::from_pem_private(
                             Config::getString(Config::SECTION_SECURITY, Config::LOCAL_PRIVATE_KEY)),
                         openssl::DigestAlgorithm::SHA256),
      id_service_verifier(openssl::EnvelopeKey::from_pem_public(
                              Config::getString(Config::SECTION_SECURITY, Config::ID_SERVICE_PUBLIC_KEY)),
                          openssl::DigestAlgorithm::SHA256),
      checkin_service_verifier(openssl::EnvelopeKey::from_pem_public(
                                   Config::getString(Config::SECTION_SECURITY, Config::CHECKIN_SERVICE_PUBLIC_KEY)),
                               openssl::DigestAlgorithm::SHA256),
      network_thread([this]() { network_io_context.run(); }) {}

PollbookClient::~PollbookClient() {
    // Shut down the IO context so the network thread can return
    network_io_context.stop();
    network_thread.join();
}

void PollbookClient::connect() {
    connect_checkin_server(Config::getString(Config::SECTION_BASIC, Config::CHECKIN_SERVICE_HOST),
                           Config::getString(Config::SECTION_BASIC, Config::CHECKIN_SERVICE_PORT));
    connect_id_server(Config::getString(Config::SECTION_BASIC, Config::ID_SERVICE_HOST),
                      Config::getString(Config::SECTION_BASIC, Config::ID_SERVICE_PORT));
    logger->info("Client connected to both check-in and ID services");
}

void PollbookClient::connect_checkin_server(const std::string& hostname, const std::string& port) {
    asio::ip::tcp::resolver server_resolver(network_io_context);
    auto resolve_results = server_resolver.resolve(hostname, port);
    asio::connect(checkin_server_socket, resolve_results);
    checkin_connected = true;
}

void PollbookClient::connect_id_server(const std::string& hostname, const std::string& port) {
    asio::ip::tcp::resolver server_resolver(network_io_context);
    auto resolve_results = server_resolver.resolve(hostname, port);
    asio::connect(id_server_socket, resolve_results);
    id_connected = true;
}

void PollbookClient::start_id_request_write(std::uint64_t timestamp, const std::vector<std::uint8_t>& voter_id_data) {
    std::uint32_t my_id = Config::getUInt32(Config::SECTION_BASIC, Config::CLIENT_ID);
    VoterIDRequest::Body validation_request_body(my_id, timestamp, voter_id_data);
    // Sign the body of the message
    std::vector<std::uint8_t> body_bytes(mutils::bytes_size(validation_request_body));
    mutils::to_bytes(validation_request_body, body_bytes.data());
    private_key_signer.init();
    private_key_signer.add_bytes(body_bytes.data(), body_bytes.size());
    // Move the body into a full message, with the signature at the end
    VoterIDRequest validation_request(std::move(validation_request_body), private_key_signer.finalize());
    // Serialize and send the message
    std::size_t message_size = mutils::bytes_size(validation_request);
    std::vector<std::uint8_t> validation_request_buffer(message_size + sizeof(message_size));
    mutils::to_bytes(message_size, validation_request_buffer.data());
    mutils::to_bytes(validation_request, validation_request_buffer.data() + sizeof(message_size));
    asio::async_write(id_server_socket,
                      asio::buffer(validation_request_buffer),
                      [this](const asio::error_code& error, std::size_t bytes_written) {
                          if(!error) {
                              logger->debug("Sent a request to verify the voter's ID to the ID service.");
                              // After sending the request, start waiting for the response, which will start with a "size" header
                              start_size_read(true);
                          } else {
                              logger->error("Error writing the ID-verification request to the ID service! Error: {}", error.message());
                              current_request_promise.set_value({false, "Network error: I/O error when sending a request to the Voter ID service"});
                          }
                      });
}

void PollbookClient::start_size_read(bool on_id_server) {
    std::shared_ptr<std::size_t> message_size = std::make_shared<std::size_t>();
    if(on_id_server) {
        asio::async_read(id_server_socket,
                         asio::buffer(&(*message_size), sizeof(std::size_t)),
                         [this, message_size](const asio::error_code& error, std::size_t bytes_read) {
                             if(!error) {
                                 logger->debug("Read {} bytes from socket into a std::size_t", bytes_read);
                                 assert(bytes_read == sizeof(std::size_t));
                                 logger->debug("Message received from ID service, size {} bytes", *message_size);
                                 start_id_response_read(*message_size);
                             } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
                                 logger->error("ID service disconnected before sending message size");
                                 current_request_promise.set_value({false, "Network error: Voter ID service disconnected"});
                             } else {
                                 logger->error("Unexpected error when reading message size from ID service: {}", error.message());
                                 current_request_promise.set_value({false, "Network error: I/O error when reading from Voter ID service"});
                             }
                         });
    } else {
        asio::async_read(checkin_server_socket,
                         asio::buffer(&(*message_size), sizeof(std::size_t)),
                         [this, message_size](const asio::error_code& error, std::size_t bytes_read) {
                             if(!error) {
                                 logger->debug("Read {} bytes from socket into a std::size_t", bytes_read);
                                 assert(bytes_read == sizeof(std::size_t));
                                 logger->debug("Message received from checkin service, size {} bytes", *message_size);
                                 start_checkin_response_read(*message_size);
                             } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
                                 logger->error("Checkin service disconnected before sending message size");
                                 current_request_promise.set_value({false, "Network error: Checkin service disconnected"});
                             } else {
                                 logger->error("Unexpected error when reading message size from checkin service: {}", error.message());
                                 current_request_promise.set_value({false, "Network error: I/O error when reading from the checkin service"});
                             }
                         });
    }
}

void PollbookClient::start_id_response_read(std::size_t message_size) {
    id_server_buffer.resize(message_size);
    asio::async_read(id_server_socket,
                     asio::buffer(id_server_buffer),
                     [this](const asio::error_code& error, std::size_t bytes_read) {
                         if(!error) {
                             assert(bytes_read == id_server_buffer.size());
                             auto response = mutils::from_bytes<VerifiedVoterID>(nullptr, id_server_buffer.data());
                             handle_id_response(*response);
                         } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
                             logger->error("ID service disconnected before sending entire response message");
                             current_request_promise.set_value({false, "Network error: Voter ID service disconnected"});
                         } else {
                             logger->error("Unexpected error when reading VerifiedVoterID from ID service: {}", error.message());
                             current_request_promise.set_value({false, "Network error: I/O error when reading from the Voter ID service"});
                         }
                     });
}

void PollbookClient::handle_id_response(const VerifiedVoterID& response) {
    // Verify the signature, then asynchronously schedule a write for the check-in request
    std::vector<std::uint8_t> response_body_bytes(mutils::bytes_size(response.presented_id));
    mutils::to_bytes(response.presented_id, response_body_bytes.data());
    id_service_verifier.init();
    id_service_verifier.add_bytes(response_body_bytes.data(), response_body_bytes.size());
    bool verified = id_service_verifier.finalize(response.id_service_signature);
    if(verified) {
        start_checkin_request_write(response);
    } else {
        current_request_promise.set_value({false, "Invalid signature from the ID verification service on the voter's ID"});
    }
}

void PollbookClient::start_checkin_request_write(const VerifiedVoterID& verified_id_response) {
    std::uint32_t my_id = Config::getUInt32(Config::SECTION_BASIC, Config::CLIENT_ID);
    auto current_time = std::chrono::system_clock::now();
    std::uint64_t current_timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                                          current_time.time_since_epoch())
                                          .count();
    CheckinRequest::Body request_body(my_id, current_timestamp, std::get<2>(current_request_voter_name),
                                      std::get<0>(current_request_voter_name), std::get<1>(current_request_voter_name),
                                      current_request_voter_id_number, verified_id_response);
    // Serialize the body of the message and sign the bytes
    std::vector<std::uint8_t> request_body_bytes(mutils::bytes_size(request_body));
    mutils::to_bytes(request_body, request_body_bytes.data());
    private_key_signer.init();
    private_key_signer.add_bytes(request_body_bytes.data(), request_body_bytes.size());
    // Construct the message, with the signature at the end
    CheckinRequest request(std::move(request_body), private_key_signer.finalize());
    // Serialize and send the message (note: this will redundantly serialize the body again)
    std::size_t message_size = mutils::bytes_size(request);
    std::vector<std::uint8_t> request_message_buffer(message_size + sizeof(message_size));
    mutils::to_bytes(message_size, request_message_buffer.data());
    mutils::to_bytes(request, request_message_buffer.data() + sizeof(message_size));
    asio::async_write(checkin_server_socket,
                      asio::buffer(request_message_buffer),
                      [this](const asio::error_code& error, std::size_t bytes_written) {
                          if(!error) {
                              logger->debug("Sent a check-in request for voter {} {} {} to check-in service.", std::get<0>(current_request_voter_name), std::get<1>(current_request_voter_name), std::get<2>(current_request_voter_name));
                              start_size_read(false);
                          } else {
                              logger->error("Error writing the ID-verification request to the ID service! Error: {}", error.message());
                              current_request_promise.set_value({false, "Network error: I/O error when sending a request to the check-in service"});
                          }
                      });
}

void PollbookClient::start_checkin_response_read(std::size_t message_size) {
    checkin_server_buffer.resize(message_size);
    asio::async_read(checkin_server_socket,
                     asio::buffer(checkin_server_buffer),
                     [this](const asio::error_code& error, std::size_t bytes_read) {
                         if(!error) {
                             assert(bytes_read == checkin_server_buffer.size());
                             auto response = mutils::from_bytes<CheckinResponse>(nullptr, checkin_server_buffer.data());
                             handle_checkin_response(*response);
                         } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
                             logger->error("Checkin service disconnected before sending entire response message");
                             current_request_promise.set_value({false, "Network error: Check-in service disconnected"});
                         } else {
                             logger->error("Unexpected error when reading CheckinResponse from check-in service: {}", error.message());
                             current_request_promise.set_value({false, "Network error: I/O error when reading from the check-in service"});
                         }
                     });
}

void PollbookClient::handle_checkin_response(const CheckinResponse& response) {
    // Serialize the body of the response to verify the signature
    std::vector<std::uint8_t> response_body_bytes(mutils::bytes_size(response.body));
    mutils::to_bytes(response.body, response_body_bytes.data());
    logger->trace("Verifying these bytes from the check-in server: {}", spdlog::to_hex(response_body_bytes));
    logger->trace("Against signature: {}", spdlog::to_hex(response.checkin_service_signature));
    checkin_service_verifier.init();
    checkin_service_verifier.add_bytes(response_body_bytes.data(), response_body_bytes.size());
    bool verified = checkin_service_verifier.finalize(response.checkin_service_signature);
    if(!verified) {
        std::string reason_string = openssl::get_error_string(ERR_get_error(), "");
        current_request_promise.set_value({false, "Invalid signature on check-in service's response. OpenSSL error: " + reason_string});
    } else if(response.body.approved) {
        current_request_promise.set_value({true, ""});
    } else {
        current_request_promise.set_value({false, "Check-in service rejected the request"});
    }
}

std::future<CheckinResult> PollbookClient::check_in_voter(const std::string& first_name, const std::string& middle_name,
                                                          const std::string& last_name,
                                                          std::uint32_t voter_id_document_number,
                                                          const std::vector<std::uint8_t>& voter_id_data) {
    if(!checkin_connected || !id_connected) {
        throw std::runtime_error("Client must be connected before calling check_in_voter!");
    }
    // Reset the promise-future pair for the current request
    current_request_promise = std::promise<CheckinResult>();

    std::uint32_t my_id = Config::getUInt32(Config::SECTION_BASIC, Config::CLIENT_ID);
    auto current_time = std::chrono::system_clock::now();
    std::uint64_t current_timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                                          current_time.time_since_epoch())
                                          .count();
    // Store these in the instance variables so they can be used later to construct the check-in request
    current_request_voter_name = std::make_tuple(first_name, middle_name, last_name);
    current_request_voter_id_number = voter_id_document_number;
    // Start the checkin process by asynchronously scheduling the write of the ID-verification request
    start_id_request_write(current_timestamp, voter_id_data);
    // Return a future that the caller can use to wait for the process to finish
    return current_request_promise.get_future();
}

void PollbookClient::send_string_message(const std::string& message) {
    if(!checkin_connected) {
        throw std::runtime_error("Client must be connected before calling send_string_message!");
    }
    // Message format: Length of the message in bytes, then body of the message
    std::vector<uint8_t> outgoing_message_buffer(sizeof(std::size_t) + message.size());
    std::size_t message_size = message.size();
    std::memcpy(outgoing_message_buffer.data(), &message_size, sizeof(message_size));
    std::memcpy(outgoing_message_buffer.data() + sizeof(message_size), message.data(), message_size);
    asio::write(checkin_server_socket, asio::buffer(outgoing_message_buffer));
}

}  // namespace epollbook
