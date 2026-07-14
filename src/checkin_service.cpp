#include "epollbook/checkin_service.hpp"
#include "epollbook/config/config.hpp"
#include "epollbook/log_utils.hpp"
#include "epollbook/trusted_client_request.hpp"
#include "epollbook/faulty_clients.hpp"
#include "epollbook/warning_query_server.hpp"

#include <shared_mutex>
#include <fstream>
#include <asio.hpp>
#include <chrono>
#include <openssl/rand.h>

#include <array>
#include <iostream>
#include <filesystem>

namespace epollbook {

CheckinService::CheckinService()
        : logger(spdlog::get(LogUtils::get_default_logger_name())),
          ssl_context(asio::ssl::context::tlsv12_server),
          connection_listener(
              network_io_context,
              asio::ip::tcp::endpoint(
                  asio::ip::tcp::tcp::v4(),
                  Config::getUInt16(Config::SECTION_BASIC, Config::CHECKIN_SERVICE_PORT))),
          id_service_verifier(openssl::EnvelopeKey::from_pem_public(
                                  Config::getString(Config::SECTION_SECURITY, Config::ID_SERVICE_PUBLIC_KEY)),
                              openssl::DigestAlgorithm::SHA256),
          signer(openssl::EnvelopeKey::from_pem_private(Config::getString(Config::SECTION_SECURITY, Config::LOCAL_PRIVATE_KEY)),
                 signature_digest_algorithm) {
    setupFaultTracking();
    FaultTracker::getInstance().initializeConfig();
    load_voter_list(Config::getString(Config::SECTION_BASIC, Config::VOTER_LIST_FILE));
    trusted_clients = load_trusted_clients(Config::getString(Config::SECTION_BASIC, Config::TRUSTED_CLIENTS_FILE));
    load_pin_mappings(Config::getString(Config::SECTION_BASIC, Config::VOTER_LIST_FILE));
    load_client_public_keys();
    configure_ssl_context(ssl_context,
                          Config::getString(Config::SECTION_SECURITY, Config::CHECKIN_SERVICE_CERT),
                          Config::getString(Config::SECTION_SECURITY, Config::LOCAL_PRIVATE_KEY),
                          Config::getString(Config::SECTION_SECURITY, Config::CA_CERT));
}

CheckinService::~CheckinService() {
    running = false;
    if (cleanupThread && cleanupThread->joinable()) {
        cleanupThread->join();
    }
    network_io_context.stop();
    network_thread.join();
}

void CheckinService::do_accept() {
    connection_listener.async_accept(
        network_io_context,
        [this](const asio::error_code& error, asio::ip::tcp::socket peer) {
            handle_accept(error, std::move(peer));
        });
}

void CheckinService::save_pub_key(const openssl::EnvelopeKey& envelope_key, std::uint32_t client_id) {
    std::stringstream pub_key_file_path_builder;
    pub_key_file_path_builder << Config::getString(Config::SECTION_SECURITY, Config::CLIENT_KEYS_FOLDER)
                              << Config::getString(Config::SECTION_SECURITY, Config::CLIENT_KEY_FILE_PREFIX)
                              << client_id << ".pem";
    std::string pkey_file_path = pub_key_file_path_builder.str();
    try {
        envelope_key.to_pem_public(pkey_file_path);
        logger->info("Successfully saved public key for client ID {} to {}", client_id, pkey_file_path);
    } catch (const std::exception& e) {
        logger->error("Error saving public key for client ID {} to {}: {}", client_id, pkey_file_path, e.what());
    }
}

void CheckinService::handle_accept(const asio::error_code& error, asio::ip::tcp::socket new_socket) {
    if (!error) {
        auto client_ip = new_socket.remote_endpoint();
        auto ssl_stream_ptr = std::make_shared<asio::ssl::stream<asio::ip::tcp::socket>>(std::move(new_socket), ssl_context);

        ssl_stream_ptr->async_handshake(asio::ssl::stream_base::server,
            [this, ssl_stream_ptr, client_ip](const asio::error_code& handshake_error) {

                if (!handshake_error) {
                    // The handshake was successful
                    X509* clientCert = SSL_get0_peer_certificate(ssl_stream_ptr->native_handle());

                    if (clientCert != nullptr) {
                        uint32_t client_id = get_client_id_from_cert(clientCert);
                        logger->debug("Client presented a certificate with ID {}", client_id);
                        {
                            std::unique_lock<std::shared_mutex> lock(client_mutex);
                            client_id_map[client_ip] = client_id;
                        }
                        // Extract the public key from the certificate

                        EVP_PKEY* pubkey = X509_get_pubkey(clientCert);
                        if (pubkey != nullptr) {
                            openssl::EnvelopeKey envelope_key(pubkey);

                            // auto it = client_public_keys.find(client_id);
                            auto [it, inserted] = client_public_keys.try_emplace(client_id, envelope_key);
                            if (!inserted) {
                                // A key for this client_id already exists
                                if(!(it->second == envelope_key)) {
                                    logger->warn("Public key mismatch for client ID {}.\nOld key:\n{}, New key:\n{}",
                                                 client_id, it->second.to_pem_public(), envelope_key.to_pem_public());
                                    FaultTracker::getInstance().reportFault(client_id, "Public key mismatch for client ID");
                                } else {
                                    logger->debug("Public key matches for client ID {}", client_id);
                                    openssl::Verifier client_verifier(envelope_key, signature_digest_algorithm);
                                    client_verifiers.emplace(client_id, std::move(client_verifier));
                                }
                            } else {
                                // New client
                                logger->info("New client connected with ID {}", client_id);
                                save_pub_key(envelope_key, client_id);
                                openssl::Verifier client_verifier(envelope_key, signature_digest_algorithm);
                                client_verifiers.emplace(client_id, std::move(client_verifier));
                                client_public_keys.emplace(client_id, envelope_key);
                            }

                            if (clients.find(client_id) == clients.end()) {
                                if (trusted_clients.find(client_id) != trusted_clients.end()) {
                                    logger->debug("Adding a new trusted client: ID {}", client_id);
                                    add_client(client_id, ClientType::TrustedClient);
                                } else {
                                    logger->debug("Adding a new untrusted client: ID {}", client_id);
                                    add_client(client_id, ClientType::UntrustedClient);
                                }
                            }
                        } else {
                            logger->error("Error extracting public key for client ID {}", client_id);
                        }
                        // Clean up
                    } else {
                        logger->error("No certificate received from client");
                    }
                    // Clean up
                    client_ssl_streams[client_ip] = ssl_stream_ptr;
                    logger->debug("Accepted a connection from client at {}", client_ip);
                    // Start a read for the message size
                    start_size_read(client_ip);
                }
                else {
                    logger->warn("Handshake failed: {}", handshake_error.message());
                    FaultTracker::getInstance().reportFault(client_id, handshake_error.message());
                }
                // Enqueue another accept operation for the connection listener so it keeps listening
                do_accept();
            });
    }
}

void CheckinService::configure_ssl_context(asio::ssl::context& ssl_context,
                                           const std::string& cert_file,
                                           const std::string& key_file,
                                           const std::string& ca_file) {
    ssl_context.use_certificate_chain_file(cert_file);
    ssl_context.use_private_key_file(key_file, asio::ssl::context::pem);
    ssl_context.set_verify_mode(asio::ssl::verify_peer);
    ssl_context.load_verify_file(ca_file);
    ssl_context.set_verify_callback(
        [](bool preverified, asio::ssl::verify_context& ctx) -> bool {
            return preverified;
        });
}

std::uint32_t CheckinService::get_client_id_from_cert(X509* cert) {
    char cn[256];
    X509_NAME* subject = X509_get_subject_name(cert);
    X509_NAME_get_text_by_NID(subject, NID_commonName, cn, sizeof(cn));
    std::string s = std::string(cn);
    std::stringstream ss(s);

    std::string id_str;
    std::getline(ss, id_str, ' ');
    std::getline(ss, id_str, ' ');
    std::uint32_t id = static_cast<std::uint32_t>(std::stoul(id_str));
    return id;
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
    asio::async_read_until(*(client_ssl_streams.at(client_ip)), *client_buffers[client_ip], "\n",
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

void CheckinService::handle_trusted_client(std::string msg_string, asio::ip::tcp::endpoint client_ip) {
    read_from_csv();

    std::string ticket, secret;
    std::uint32_t id, pin;
    nlohmann::json json;
    try {
        json = nlohmann::json::parse(msg_string);
    } catch(nlohmann::json::parse_error& err) {
        logger->error("Failed to parse message as Trusted Client JSON due to error: {}", err.what());
        return;
    }
    std::unique_ptr<TicketRequest> req;
    try {
        req = std::make_unique<TicketRequest>(TicketRequest::FromJson(json));
    } catch (const nlohmann::json::exception& ex) {
        logger->warn("JSON parsing error: {}", ex.what());
        FaultTracker::getInstance().reportFault(client_id, ex.what());
        return;
    } catch (const std::runtime_error& ex) {
        logger->warn("TicketRequest creation error: {}", ex.what());
        FaultTracker::getInstance().reportFault(client_id, ex.what());
        return;
    } catch (const std::exception& ex) {
        logger->warn("Unexpected error: {}", ex.what());
        FaultTracker::getInstance().reportFault(client_id, ex.what());
        return;
    }

    TicketRequest request = std::move(*req);
    uint32_t client_id = client_id_map[client_ip];
    if (request.body.client_id != client_id) {
        logger->warn("Client ID in the message and the client ID in the public key do not match!");
        FaultTracker::getInstance().reportFault(client_id, "Client ID in the message and the client ID in the public do not match!");
    }
    auto t_it = client_tickets_map.find(request.body.ticket);
    if (t_it == client_tickets_map.end()) {
        logger->warn("Client ticket in the message and the client ticket in the server do not match!");
        FaultTracker::getInstance().reportFault(client_id, "Client ID in the message and the client ID in the public do not match!");
        return;
    }
    const uint32_t voter_id = t_it->second.first;

    std::stringstream ss;
    std::string pin_str;
    ss << request.body.pin;
    ss >> pin_str;

    std::map<std::string, std::string> voter_info = find_voter(
        Config::getString(
            Config::SECTION_BASIC, Config::VOTER_LIST_FILE
        ),
        voter_id
    );
    if (std::to_string(request.body.pin) != voter_info["pin"]) {
        logger->warn("Wrong Pin!");
        TicketResponse::Body response_body(
            false,
            voter_info["last_name"],
            voter_info["first_name"],
            voter_info["middle_name"],
            voter_id,
            "",
            request.body.pin
        );
        nlohmann::json body_json = TicketResponse::Body::ToJson(response_body);
        std::string body_string = body_json.dump();
        signer.init();
        signer.add_bytes(body_string.data(), body_string.size());
        TicketResponse response(std::move(response_body), signer.finalize());
        std::string response_str = TicketResponse::ToJson(response).dump() + "\n";
        asio::error_code ec;
        asio::write(*(client_ssl_streams.at(client_ip)), asio::buffer(response_str), ec);
        if (ec) {
            logger->debug("Failed sending wrong-PIN denial: {}", ec.message());
        }
        return;
    }
    if(client_verifiers.find(request.body.client_id) == client_verifiers.end()) {
        if(!load_client_public_key(request.body.client_id)) {
            logger->warn("Could not load the public key for client number {}. Ignoring a voter ID validation request.", request.body.client_id);
            FaultTracker::getInstance().reportFault(client_id, "Could not load the public key for client. Ignoring a voter ID validation request.");
            return;
        }
    }
    // Verify the client's signature on the message
    std::string request_body_str = TicketRequest::Body::ToJson(request.body).dump();

    openssl::Verifier& verifier = client_verifiers.at(request.body.client_id);
    verifier.init();
    verifier.add_bytes(request_body_str.data(), request_body_str.size());
    

    std::shared_ptr<Timer> timer;
    bool timer_valid = false;
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = request_timers.find(voter_id);
        if (it != request_timers.end()) {
            timer = it->second;

            // Check if the request is within the valid time range
            auto now = std::chrono::steady_clock::now();
            auto expiry_time = timer->timer.expiry();

            // Get the configured timeout interval in minutes
            int time_interval = Config::getInt32(Config::SECTION_SECURITY, Config::TIMEOUT_INTERVAL);
            auto start_time = expiry_time - std::chrono::minutes(time_interval);

            // Check if current time is within the valid window
            if (now >= start_time && now <= expiry_time) {
                timer_valid = true;
                // Remove the timer from the map since we're handling it now
                request_timers.erase(it);
            } else {
                logger->warn("Trusted client request for voter ID {} is outside the valid time window", voter_id);
                FaultTracker::getInstance().reportFault(client_id, "Request outside valid time window");
            }
        } else {
            logger->warn("No timer found for voter ID {}", voter_id);
            FaultTracker::getInstance().reportFault(client_id, "No timer found for voter ID");
        }
    }

    if(!verifier.finalize(request.signature)) {
        logger->debug("Rejecting client {}'s request because the client's signature on the message was invalid",
                    request.body.client_id);
        return;
    }

    if (client_tickets_map.find(request.body.ticket) != client_tickets_map.end() && timer_valid) {
        auto find_voter_result = voter_status_table.find(voter_id);
        if(find_voter_result != voter_status_table.end()) {
            if(find_voter_result->second == VoterStatus::PENDING) {
                find_voter_result->second = VoterStatus::CHECKED_IN;
            }
        }
        std::pair pair = client_tickets_map[request.body.ticket];
        id = pair.first;
        secret = pair.second;
        TicketResponse::Body response_body(
            true,
            voter_info["last_name"],
            voter_info["first_name"],
            voter_info["middle_name"],
            voter_id,
            secret,
            request.body.pin
        );


        // Cancel the timer
        timer->timer.cancel();

        nlohmann::json body_json = TicketResponse::Body::ToJson(response_body);
        std::string body_string = body_json.dump();
        signer.init();
        signer.add_bytes(body_string.data(), body_string.size());
        TicketResponse response(std::move(response_body), signer.finalize());
        std::string response_str = TicketResponse::ToJson(response).dump() + "\n";
        asio::error_code ec;
        asio::write(*(client_ssl_streams.at(client_ip)), asio::buffer(response_str), ec);
        if (!ec) {
            logger->debug("Sent message to Client");
        } else {
            logger->debug("Failed sending message: {}", ec);
        }
    }
    else {
        std::map<std::string,std::string> voter_info;
        voter_info = find_voter(Config::getString(Config::SECTION_BASIC, Config::VOTER_LIST_FILE),
                                voter_id);
        TicketResponse::Body response_body(
            false,
            voter_info["last_name"],
            voter_info["first_name"],
            voter_info["middle_name"],
            voter_id,
            "",
            request.body.pin
        );
        nlohmann::json body_json = TicketResponse::Body::ToJson(response_body);
        std::string body_string = body_json.dump();
        signer.init();
        signer.add_bytes(body_string.data(), body_string.size());
        TicketResponse response(std::move(response_body), signer.finalize());
        std::string response_str = TicketResponse::ToJson(response).dump() + "\n";
        asio::error_code ec;
        asio::write(*(client_ssl_streams.at(client_ip)), asio::buffer(response_str), ec);
        if (!ec) {
            logger->debug("Sent message to Client");
        } else {
            logger->debug("Failed sending message: {}", ec);
        }
        if (!timer) {
            logger->warn("Request was timed out");
            FaultTracker::getInstance().reportFault(client_id, "Request was timed out");
        }
        logger->warn("Invalid ticket");
        FaultTracker::getInstance().reportFault(client_id, "Invalid ticket");
    }
}

void CheckinService::start_payload_read(asio::ip::tcp::endpoint client_ip, std::size_t size_of_message) {
    // Creating a shared pointer to hold the message content.
    auto msg = std::make_shared<std::string>();

    // Initialize a new buffer for this client if not already present.
    if (client_buffers.find(client_ip) == client_buffers.end()) {
        client_buffers[client_ip] = std::make_shared<asio::streambuf>();
    }
    // Asynchronous read until a newline character to get the payload.
    asio::async_read_until(*(client_ssl_streams.at(client_ip)), *client_buffers[client_ip], "\n",
            [this, client_ip, size_of_message, msg](const asio::error_code& error, std::size_t bytes_read) {
                if (!error) {
                    // Successfully read the payload.
                    if (size_of_message == bytes_read - 1) {
                        *msg = std::string(asio::buffer_cast<const char*>(this->client_buffers[client_ip]->data()), bytes_read);
                        std::string msg_string = *msg;

                        // Consume the bytes that were read.
                        client_buffers[client_ip]->consume(bytes_read);

                        logger->debug("Finished reading message of size {} from client at {}", bytes_read, client_ip);

                        ClientType type;
                        {
                            std::shared_lock<std::shared_mutex> lock(client_mutex);
                            auto it = client_id_map.find(client_ip);
                            if (it == client_id_map.end()) {
                                logger->warn("Unknown client IP");
                                FaultTracker::getInstance().reportFault(client_id, "Unknown client IP");
                                return;
                            }
                            client_id = it->second;
                            auto client_it = clients.find(client_id);
                            if (client_it == clients.end()) {
                                logger->warn("Unknown client ID");
                                FaultTracker::getInstance().reportFault(client_id, "Unknown client ID");
                                return;
                            }
                            type = client_it->second.type;
                        }
                        switch (type) {
                            case ClientType::TrustedClient: {
                                logger->debug("Received a message from a trusted client: {}", msg_string);
                                handle_trusted_client(msg_string, client_ip);
                                break;
                            }
                            case ClientType::UntrustedClient: {
                                logger->debug("Received a message from an untrusted client: {}", msg_string);
                                nlohmann::json json;
                                try {
                                    // Parse the JSON payload.
                                    json = nlohmann::json::parse(msg_string);
                                } catch(const nlohmann::json::parse_error& e) {
                                    // Failed to parse the JSON payload.
                                    logger->debug("Failed to parse JSON: {}", e.what());
                                }
                                CheckinRequest request = CheckinRequest::FromJson(json);
                                handle_checkin_request(client_ip, request);
                                break;
                            }
                        }
                    } else {
                        // Message size mismatch.
                        logger->warn("Size of the message does not match the size that is received from the server for the client {}", client_ip);
                        FaultTracker::getInstance().reportFault(client_id, "Size of the message does not match the size that is received from the server for the client ");
                        client_sockets.erase(client_ip);
                    }
                } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
                    // Client disconnected before sending the entire message.
                    logger->debug("Client at {} disconnected before sending entire message", client_ip);
                    client_sockets.erase(client_ip);
                } else {
                    // Unexpected I/O error.
                    logger->warn("Unexpected I/O error when reading a request message from client {}. Error: {}", client_ip, error.message());
                    FaultTracker::getInstance().reportFault(client_id, "Size of the message does not match the size that is received from the server for the client ");
                }
    });
}

std::string CheckinService::generate_secret(int length) {
    unsigned char buffer[length];
    if (RAND_bytes(buffer, length) != 1) {
        throw std::runtime_error("Failed to generate secret");
    }
    std::stringstream ss;
    for (int i = 0; i < length; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);
    }
    return ss.str();
}

void CheckinService::read_from_csv() {
    std::ifstream file("ticket_validation.csv", std::ios::in);
    if (!file.is_open()) {
        std::cerr << "Error opening the file\n";
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string id_str, ticket, secret;

        if (std::getline(iss, ticket, ',') &&
            std::getline(iss, id_str, ',') &&
            std::getline(iss, secret)) {

            try {
                std::uint32_t id = static_cast<std::uint32_t>(std::stoul(id_str));
                client_tickets_map[ticket] = std::make_pair(id, secret);
            } catch (const std::invalid_argument& e) {
                std::cerr << "Invalid ID format: " << id_str << std::endl;
            } catch (const std::out_of_range& e) {
                std::cerr << "ID out of range: " << id_str << std::endl;
            }
        } else {
            std::cerr << "Invalid line format: " << line << std::endl;
        }
    }
}

void CheckinService::write_to_csv(const std::string& ticket, const std::string& secret, const std::uint32_t& id) {
    std::ofstream file("ticket_validation.csv", std::ios::app);
    if (file.is_open()) {
        file << ticket << "," << id << "," << secret << std::endl;
        file.close();
    } else
        logger->warn("Error: Unable to write to CSV file");
}

void CheckinService::handle_checkin_request(const asio::ip::tcp::endpoint& client_ip, const CheckinRequest& request) {
    // Ensure the client id in the message matches the TLS-authenticated (cert-derived) client id
    uint32_t client_id = client_id_map[client_ip];
    bool identity_ok = (request.body.client_id_num == client_id);
    if (!identity_ok) {
        // The client is claiming to be a different client (spoofed identity). Reject it, file a
        // fault, and fall through to send a signed approved=false response. We must NOT try to
        // load request.body.client_id_num's public key on its say-so — a missing key file would
        // otherwise drive a request for an identity we never authenticated (and historically
        // crashed the server via an uncaught file_not_found).
        logger->warn("Rejecting check-in request: claimed client_id_num {} does not match TLS-authenticated client {} (spoofed client identity)",
                     request.body.client_id_num, client_id);
        FaultTracker::getInstance().reportFault(client_id, "Claimed client_id_num does not match TLS-authenticated client identity");
    }

    auto current_time = std::chrono::system_clock::now();
    uint64_t current_timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     current_time.time_since_epoch())
                                     .count();
    bool accept = false;

    nlohmann::json j = CheckinRequest::Body::ToJson(request.body);
    std::string cpp_dump = j.dump();
    std::string cpp_base64 = Base64::encode(
        reinterpret_cast<const uint8_t*>(cpp_dump.data()),
        cpp_dump.size());
    nlohmann::json request_json = CheckinRequest::ToJson(request);
    std::string request_message_string = request_json.dump();

    if (identity_ok) {
        // Ensure the public key for this client is in memory
        if(client_verifiers.find(request.body.client_id_num) == client_verifiers.end()) {
            if(!load_client_public_key(request.body.client_id_num)) {
                logger->warn("Could not load the public key for client number {}. Ignoring a voter ID validation request.", request.body.client_id_num);
                return;
            }
        }

        if(validate_client_request(request, current_timestamp)) {
            auto find_voter_result = voter_status_table.find(request.body.voter_unique_id);
            if(find_voter_result != voter_status_table.end()) {
                if(find_voter_result->second == VoterStatus::ELIGIBLE) {
                    find_voter_result->second = VoterStatus::PENDING;
                    logger->debug("Accepted a check-in request for voter {} {} {} (UID {}) from client {}",
                                  request.body.first_name, request.body.middle_name, 
                                  request.body.last_name, request.body.voter_unique_id, 
                                  request.body.client_id_num);
                    accept = true;
                    start_timer(request.body.voter_unique_id);
                } else {
                    std::cout << "Voter not found\n";
                    logger->debug("Rejecting client {}'s check-in request for {} {} {} (UID {}) because the voter has already checked in",
                                  request.body.client_id_num, request.body.first_name, 
                                  request.body.middle_name, request.body.last_name, 
                                  request.body.voter_unique_id);
                }
            } else {
                logger->debug("Rejecting client {}'s check-in request for  {} {} {} (UID {}) because the voter is not in the server's voter status table",
                               request.body.client_id_num, request.body.first_name, request.body.middle_name, request.body.last_name, request.body.voter_unique_id);
            }
        }
    }


    std::string ticket;
    std::string secret;
    if (accept) {
        ticket = generate_secret(16);
        secret = generate_secret(32);
        client_tickets_map[ticket] = std::make_pair(request.body.voter_unique_id, secret);
        write_to_csv(ticket, secret, request.body.voter_unique_id);
    } else {
        ticket = "";
        secret = "";
    }
    CheckinResponse::Body response_body(accept, request.body.client_id_num,
                                        current_timestamp, request.body.last_name, 
                                        request.body.first_name, request.body.middle_name, 
                                        request.body.voter_unique_id, ticket);
    // Sign the body of the response message with the service's key
    std::string response_body_str = CheckinResponse::Body::ToJson(response_body).dump();


    signer.init();
    signer.add_bytes(response_body_str.data(), response_body_str.size());
    // Serialize and send the response message, including the signature
    CheckinResponse response(std::move(response_body), signer.finalize());

    // convert response into json and convert it into a string
    nlohmann::json response_json = CheckinResponse::ToJson(response);

    std::string response_message_string = response_json.dump();
    std::size_t response_size = response_message_string.size();
    std::string response_string = std::to_string(response_size) + "\n" + response_message_string +"\n";

    logger->debug("Sending a response of size {} to client at {}: {}", response_size, client_ip, response_message_string);
    asio::write(*(client_ssl_streams.at(client_ip)), asio::buffer(response_string));
    // Enqueue another read operation for the next message from this client (if any)
    start_size_read(client_ip);
}
void CheckinService::start_timer(const std::uint32_t voter_id) {
    auto timer = std::make_shared<Timer>(network_io_context);
    int time_interval = Config::getInt32(Config::SECTION_SECURITY, Config::TIMEOUT_INTERVAL);
    timer->voter_id = voter_id;
    timer->timer.expires_after(std::chrono::minutes(time_interval));

    {
        std::lock_guard<std::mutex> lock(mtx);
        request_timers[voter_id] = timer;
    }

    timer->timer.async_wait([this, voter_id](const std::error_code& ec) {
        if (!ec) {
            handle_verification_timeout(voter_id);
        }
    });
}

void CheckinService::handle_verification_timeout(const std::uint32_t voter_id) {
    logger->debug("Check-in request for voter {} timed out", voter_id);
    std::lock_guard<std::mutex> unlock(mtx);
    request_timers.erase(voter_id);

    auto it = voter_status_table.find(voter_id);
    if (it != voter_status_table.end() && it->second == VoterStatus::PENDING) {
        it->second = VoterStatus::ELIGIBLE;
        logger->debug("Reverted voter {} from PENDING back to ELIGIBLE after check-in timeout", voter_id);
    }
}

bool CheckinService::validate_client_request(const CheckinRequest& request, std::uint64_t current_timestamp) {
    // Verify the client's signature on the message
    std::string request_body_str = CheckinRequest::Body::ToJson(request.body).dump();

    openssl::Verifier& verifier = client_verifiers.at(request.body.client_id_num);
    verifier.init();
    verifier.add_bytes(request_body_str.data(), request_body_str.size());

    if(!verifier.finalize(request.client_signature)) {
        logger->warn("Rejecting client {}'s check-in request for {} {} {} (UID {}) because the client's signature on the message was invalid",
                      request.body.client_id_num, request.body.first_name, request.body.middle_name, request.body.last_name, request.body.voter_unique_id);
        FaultTracker::getInstance().reportFault(client_id, "Invalid client signature on check-in request (tampered body)");
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

    // ID-service signature is valid; reject if the client claims a different voter than the ID service verified (cross-identity forwarding)
    if (request.body.voter_unique_id != request.body.verified_id_message.voter_unique_id) {
        logger->warn("Rejecting client {}'s check-in: claimed UID {} != ID-verified UID {} (cross-identity forwarding)",
                     request.body.client_id_num, request.body.voter_unique_id, request.body.verified_id_message.voter_unique_id);
        FaultTracker::getInstance().reportFault(client_id, "Claimed voter UID does not match ID-service-verified UID");
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
    logger->debug("Client {}'s check-in request passed validation", request.body.client_id_num);
    return true;
}


void CheckinService::run() {
    // Post the first asynchronous accept
    do_accept();
    startFaultCleanupThread();
    logger->info("Check-in service started on port {}", 
                 Config::getUInt16(Config::SECTION_BASIC, Config::CHECKIN_SERVICE_PORT));
    WarningQueryServer warning_query_server(network_io_context, 9000);
    warning_query_server.start_accept();

    network_io_context.run();
}

bool CheckinService::load_client_public_key(std::uint32_t client_id) {
    std::stringstream key_file_path_builder;
    key_file_path_builder << Config::getString(Config::SECTION_SECURITY, Config::CLIENT_KEYS_FOLDER) << "/"
                          << Config::getString(Config::SECTION_SECURITY, Config::CLIENT_KEY_FILE_PREFIX) << client_id << ".pem";
    std::string key_file_path = key_file_path_builder.str();
    try {
        openssl::EnvelopeKey envelope_key(openssl::EnvelopeKey::from_pem_public(key_file_path));
        client_public_keys.emplace(client_id, envelope_key);
        openssl::Verifier client_verifier(envelope_key, signature_digest_algorithm);
        client_verifiers.emplace(client_id, std::move(client_verifier));
     } catch(const std::exception& err) { 
        logger->error("Could not load public key for client {} from file {}: {}", client_id, key_file_path, err.what());
        return false;
    }
    return true;
}

std::map<std::string, std::string> CheckinService::find_voter(const std::string& csv_file_path, uint32_t id) {

    std::ifstream file(csv_file_path);
    std::map<std::string, std::string> voter_info;
    if (!file.is_open()) {
        std::cerr << "Error opening the file\n";
    }

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string uid, last_name, first_name, middle_name, addr, city, state, zip, pin_str;

        if (std::getline(iss, uid, ',') &&
            std::getline(iss, pin_str, ',') &&
            std::getline(iss, last_name, ',') &&
            std::getline(iss, first_name, ',') &&
            std::getline(iss, middle_name, ',') &&
            std::getline(iss, addr, ',') &&
            std::getline(iss, city, ',') &&
            std::getline(iss, state, ',') &&
            std::getline(iss, zip)) {
            if (uid == std::to_string(id)) {
                voter_info["voter_id"] = id;
                voter_info["last_name"] = last_name;
                voter_info["first_name"] = first_name;
                voter_info["middle_name"] = middle_name;
                voter_info["pin"] = pin_str;
                break;
            }
        } else {
            std::cerr << "Invalid line format: " << line << std::endl;
        }
    }
    return voter_info;
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

bool CheckinService::load_client_public_keys() {
    std::stringstream key_folder_path_builder;
    key_folder_path_builder << Config::getString(Config::SECTION_SECURITY, Config::CLIENT_KEYS_FOLDER) << "/";
    std::string key_folder_path = key_folder_path_builder.str();
    namespace fs = std::filesystem;
    fs::path p(key_folder_path);
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    if (ec) {
        logger->error("mkdirs {}: {}", p.parent_path().string(), ec.message());
    }

    try{
        for(const auto &entry : std::filesystem::directory_iterator(key_folder_path)) {
            openssl::EnvelopeKey key = openssl::EnvelopeKey::from_pem_public(entry.path());
            std::string key_file_name = entry.path().filename().string();
            std::string key_file_no_ext = key_file_name.substr(0, key_file_name.find_last_of("."));
            std::string prefix_to_remove = Config::getString(Config::SECTION_SECURITY, Config::CLIENT_KEY_FILE_PREFIX);
            std::uint32_t client_id = std::stoul(key_file_no_ext.erase(key_file_no_ext.find(prefix_to_remove), prefix_to_remove.size()));

            openssl::Verifier client_verifier(key, signature_digest_algorithm);
            client_verifiers.emplace(client_id, std::move(client_verifier));

            client_public_keys.emplace(client_id, std::move(key));
        }
    } catch(openssl::openssl_error& err) {
        logger->error("Could not load public keys due to openssl error {}", err.what());
        return false;
    }
    return true;
}

void CheckinService::add_client(uint32_t client_id, ClientType type) {
    std::unique_lock<std::shared_mutex> lock(client_mutex);
    clients[client_id] = ClientInfo(client_id, type);
}

void CheckinService::load_pin_mappings(const std::string& csv_file_path) {
    std::ifstream file(csv_file_path);

    if (!file.is_open()) {
        std::cerr << "Error opening the file\n";
    }

    std::string line;
    // Skip header line if present
    std::getline(file, line);

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string uid, pin, last_name, first_name, middle_name, addr, city, state, zip;

        if (std::getline(iss, uid, ',') &&
            std::getline(iss, pin, ',') &&
            std::getline(iss, last_name, ',') &&
            std::getline(iss, first_name, ',') &&
            std::getline(iss, middle_name, ',') &&
            std::getline(iss, addr, ',') &&
            std::getline(iss, city, ',') &&
            std::getline(iss, state, ',') &&
            std::getline(iss, zip)) {

            // Remove any whitespace from the PIN
            // pin.erase(std::remove_if(pin.begin(), pin.end(), ::isspace), pin.end());
            // Store the PIN -> voter ID mapping
            pin_to_voter_id[pin] = uid;
        } else {
            std::cerr << "Invalid line format: " << line << std::endl;
        }
    }

    file.close();
}

std::unordered_set<uint32_t> CheckinService::load_trusted_clients(const std::string& filename) {
    std::unordered_set<uint32_t> trusted_clients;
    std::ifstream file(filename);
    std::string line;

    if (!file.is_open()) {
        throw std::runtime_error("Unable to open file: " + filename);
    }

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        uint32_t client_id;
        if (iss >> client_id) {
            trusted_clients.insert(client_id);
        }
    }
    logger->debug("Loaded the set of trusted client IDs from file {}: {}", filename, trusted_clients);
    return trusted_clients;
}

void CheckinService::setupFaultTracking() {
    if(Config::getInstance().hasKey(Config::SECTION_BASIC, "fault_cleanup_hours")) {
        cleanup_threshold = std::chrono::hours(
            Config::getInt32(Config::SECTION_BASIC, "fault_cleanup_hours")
        );
    } else {
        cleanup_threshold = std::chrono::hours(24);
    }
}

void CheckinService::startFaultCleanupThread() {
    cleanupThread = std::make_unique<std::thread>([this]() {
        while (running) {
            FaultTracker::getInstance().clearOldRecords(cleanup_threshold);
            std::this_thread::sleep_for(std::chrono::hours(1));
        }
    });
}

}  // namespace epollbook
