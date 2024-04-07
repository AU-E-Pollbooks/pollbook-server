#include "epollbook/checkin_service.hpp"
#include "epollbook/config/config.hpp"
#include "epollbook/log_utils.hpp"

#include <asio.hpp>

#include <array>
#include <iostream>

namespace epollbook {

CheckinService::CheckinService()
        : logger(spdlog::get(LogUtils::get_default_logger_name())),
          ssl_context(asio::ssl::context::tlsv12_server),
          connection_listener(
                  network_io_context,
                  asio::ip::tcp::endpoint(
                      asio::ip::tcp::tcp::v4(), 
                      Config::getUInt16(Config::SECTION_BASIC, Config::ID_SERVICE_PORT))),
          id_service_verifier(openssl::EnvelopeKey::from_pem_public(
                                  Config::getString(Config::SECTION_SECURITY, Config::ID_SERVICE_PUBLIC_KEY)),
                              openssl::DigestAlgorithm::SHA256),
          signer(openssl::EnvelopeKey::from_pem_private(Config::getString(Config::SECTION_SECURITY, Config::LOCAL_PRIVATE_KEY)),
                 signature_digest_algorithm) {
    load_voter_list(Config::getString(Config::SECTION_BASIC, Config::VOTER_LIST_FILE));
    network_thread = std::thread([&] {
        network_io_context.run();
    });
    configure_ssl_context(ssl_context,
                      "/pollbook-server/build/apps/local-test-deployment/server0/cert.pem",
                      "/pollbook-server/build/apps/local-test-deployment/server0/private_key.pem", 
                      "/pollbook-server/build/apps/local-test-deployment/server0/ca/ca.pem")
}

CheckinService::~CheckinService() {
    network_io_context.stop();
    if (network_thread.joinable()) {
        network_thread.join();
    }
}

void CheckinService::do_accept() {
    connection_listener.async_accept(
            network_io_context,
            [this](const asio::error_code& error, asio::ip::tcp::socket peer) {
                handle_accept(error, std::move(peer));
            });
}

void CheckinService::handle_accept(const asio::error_code& error, asio::ip::tcp::socket new_socket) {
    if (!error) {
        /* auto ssl_stream = std::make_shared<asio::ssl::stream<asio::ip::tcp::socket>>(std::move(new_socket), ssl_context); */
        auto ssl_stream_ptr = std::make_shared<asio::ssl::stream<asio::ip::tcp::socket>>(std::move(new_socket), ssl_context);
        auto client_endpoint = ssl_stream_ptr->lowest_layer().remote_endpoint();

        ssl_stream_ptr->async_handshake(asio::ssl::stream_base::server,
            [this, ssl_stream_ptr, client_endpoint](const asio::error_code& handshake_error) {
                if (!handshake_error) {
                    // The handshake was successful
                    // You can now read or write to the socket
                    /* asio::ip::tcp::endpoint client_ip = new_socket.remote_endpoint(); */
                    auto client_ip = ssl_stream_ptr->lowest_layer().remote_endpoint();
                    client_ssl_streams[client_endpoint] = ssl_stream_ptr;
                    logger->debug("Accepted a connection from client at {}", client_ip);
                    // Put the new socket in the map
                    client_sockets.emplace(client_ip, ssl_stream_ptr);
                    // Start a read for the message size
                    start_size_read(client_ip);
                    // Enqueue another accept operation for the connection listener so it keeps listening
                    do_accept();
                }
                else {
                    logger->warn("Handshake failed: {}", handshake_error.message());
                }
            });
    }
}

void CheckinService::configure_ssl_context(asio::ssl::context& ssl_context, 
                           const std::string& cert_file, 
                           const std::string& key_file, 
                           const std::string& ca_file) {
    ssl_context.use_certificate_chain_file(cert_file);
    ssl_context.use_private_key_file(key_file, asio::ssl::context::pem);
    ssl_context.load_verify_file(ca_file);
    ssl_context.set_verify_mode(asio::ssl::verify_peer);
    ssl_context.set_verify_callback(
        [](bool preverified, asio::ssl::verify_context& ctx) -> bool {
            // Here, you can implement additional verification logic if necessary
            return preverified;
        });
}

void CheckinService::start_size_read(asio::ip::tcp::endpoint client_ip) {
    // Creating shared pointers to hold message size and message content.
    auto message_size = std::make_shared<std::size_t>();
    auto msg = std::make_shared<std::string>();
    std::shared_ptr<std::string> msg_size_str = std::make_shared<std::string>();

    // Initialize a new buffer for this client if not already present.
    if (client_buffers.find(client_ip) == client_buffers.end()) {
        client_buffers[client_ip] = std::make_shared<asio::streambuf>();
    }
    // Asynchronous read until a newline character to get the message size.
    asio::async_read_until(client_sockets.at(client_ip), *client_buffers[client_ip], "\n", 
        [this, client_ip, message_size, msg_size_str, msg](const asio::error_code& error, std::size_t bytes_read) {
            if (!error) {
                // Successfully read the message size.
                *msg_size_str = std::string(asio::buffer_cast<const char*>(this->client_buffers[client_ip]->data()), bytes_read);
                *message_size = std::stoul(*msg_size_str);
                logger->debug("Client at {}: Message size is {} bytes", client_ip, *message_size);

                // Consume the bytes that were read.
                this->client_buffers[client_ip]->consume(bytes_read);

                // Start reading the payload now that we know its size.
                start_payload_read(client_ip, *message_size);
            } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
                // Client disconnected before sending the message size.
                logger->debug("Client at {} disconnected before sending message size", client_ip);
                client_sockets.erase(client_ip);
            }
        });
}

void CheckinService::start_payload_read(asio::ip::tcp::endpoint client_ip, std::size_t size_of_message) {
    // Creating a shared pointer to hold the message content.
    auto msg = std::make_shared<std::string>();

    // Initialize a new buffer for this client if not already present.
    if (client_buffers.find(client_ip) == client_buffers.end()) {
        client_buffers[client_ip] = std::make_shared<asio::streambuf>();
    }
    // Asynchronous read until a newline character to get the payload.
    asio::async_read_until(client_sockets.at(client_ip), *client_buffers[client_ip], "\n",
            [this, client_ip, size_of_message, msg](const asio::error_code& error, std::size_t bytes_read) {
                if (!error) {
                    // Successfully read the payload.
                    if (size_of_message == bytes_read - 1) {
                        *msg = std::string(asio::buffer_cast<const char*>(this->client_buffers[client_ip]->data()), bytes_read);
                        std::string json_string = *msg;

                        // Consume the bytes that were read.
                        client_buffers[client_ip]->consume(bytes_read);

                        logger->debug("Finished reading message of size {} from client at {}", bytes_read, client_ip);
                        // Parse the JSON payload.
                        try {
                            nlohmann::json json = nlohmann::json::parse(json_string);
                            CheckinRequest request = CheckinRequest::FromJson(json);
                            handle_checkin_request(client_ip, request);
                        } catch(const nlohmann::json::parse_error& e) {
                            // Failed to parse the JSON payload.
                            logger->debug("Failed to parse JSON: {}", e.what());
                        }
                    } else {
                        // Message size mismatch.
                        logger->warn("Size of the message does not match the size that is received from the server for the client {}", client_ip);
                        client_sockets.erase(client_ip);
                    }
                } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
                    // Client disconnected before sending the entire message.
                    logger->debug("Client at {} disconnected before sending entire message", client_ip);
                    client_sockets.erase(client_ip);
                } else {
                    // Unexpected I/O error.
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
    std::string response_body_str = CheckinResponse::Body::ToJson(response_body).dump();

    signer.init();
    signer.add_bytes(response_body_str.data(), response_body_str.size());
    // Serialize and send the response message, including the signature
    CheckinResponse response(std::move(response_body), signer.finalize());
    
    // convert response into json and convert it into a string
    logger->debug("Serializing response");
    nlohmann::json response_json = CheckinResponse::ToJson(response);

    logger->debug("sending message");
    std::size_t response_size = response_json.size();
    std::string response_message_string = response_json.dump();
    std::string response_string = std::to_string(response_size) + "\n" + response_message_string +"\n";

    logger->debug("Sending a response of size {} to client at {}", response_size, client_ip);
    asio::write(client_sockets.at(client_ip), asio::buffer(response_string));
    // Enqueue another read operation for the next message from this client (if any)
    start_size_read(client_ip);
}

bool CheckinService::validate_client_request(const CheckinRequest& request, std::uint64_t current_timestamp) {
    // Verify the client's signature on the message
    std::string request_body_str = CheckinRequest::Body::ToJson(request.body).dump();

    openssl::Verifier& verifier = client_verifiers.at(request.body.client_id_num);
    verifier.init();
    verifier.add_bytes(request_body_str.data(), request_body_str.size());

    if(!verifier.finalize(request.client_signature)) {
        logger->debug("Rejecting client {}'s check-in request for {} {} {} (UID {}) because the client's signature on the message was invalid",
                      request.body.client_id_num, request.body.first_name, request.body.middle_name, request.body.last_name, request.body.voter_unique_id);
        return false;
    }
    // If the client's signature was valid, verify the ID service's signature
    nlohmann::json voter_id_json;
    voter_id_json["presented_id"] = VoterIDRequest::ToJson(request.body.verified_id_message.presented_id);
    voter_id_json["voter_unique_id"] = request.body.verified_id_message.voter_unique_id;
    std::string id_msg = voter_id_json.dump();

    id_service_verifier.init();
    id_service_verifier.add_bytes(id_msg.data(), id_msg.size());
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
