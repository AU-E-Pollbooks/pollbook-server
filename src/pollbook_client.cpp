#include "epollbook/pollbook_client.hpp"
#include "epollbook/checkin_request.hpp"
#include "epollbook/config/config.hpp"
#include "epollbook/openssl/signature.hpp"
#include "epollbook/voter_id_request.hpp"
#include "epollbook/trusted_client_request.hpp"

#include <asio.hpp>
#include <asio/ssl.hpp>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace epollbook {

PollbookClient::PollbookClient()
        : logger(spdlog::get(LogUtils::get_default_logger_name())),
          network_work_guard(network_io_context.get_executor()),
          ssl_context_id(asio::ssl::context::tlsv12_client),
          ssl_context_checkin(asio::ssl::context::tlsv12_client),
          id_server_socket(network_io_context, ssl_context_id),
          checkin_server_socket(network_io_context, ssl_context_checkin),
          checkin_connected(false),
          id_connected(false),
          private_key_signer(openssl::EnvelopeKey::from_pem_private(
                                 Config::getString(Config::SECTION_SECURITY, Config::LOCAL_PRIVATE_KEY)),
                             openssl::DigestAlgorithm::SHA256),
          // id_service_verifier(openssl::EnvelopeKey::from_pem_public(
          //                         Config::getString(Config::SECTION_SECURITY, Config::ID_SERVICE_PUBLIC_KEY)),
          //                     openssl::DigestAlgorithm::SHA256),
          // checkin_service_verifier(openssl::EnvelopeKey::from_pem_public(
          //                              Config::getString(Config::SECTION_SECURITY, Config::CHECKIN_SERVICE_PUBLIC_KEY)),
          //                          openssl::DigestAlgorithm::SHA256),
          network_thread([this]() { network_io_context.run(); }) {
              configure_ssl_context(ssl_context_id, 
                    id_server_socket,
                    Config::getString(Config::SECTION_SECURITY, Config::LOCAL_CERT),
                    Config::getString(Config::SECTION_SECURITY, Config::LOCAL_PRIVATE_KEY),
                    Config::getString(Config::SECTION_SECURITY, Config::CA_CERT));
              configure_ssl_context(ssl_context_checkin, 
                    checkin_server_socket,
                    Config::getString(Config::SECTION_SECURITY, Config::LOCAL_CERT),
                    Config::getString(Config::SECTION_SECURITY, Config::LOCAL_PRIVATE_KEY),
                    Config::getString(Config::SECTION_SECURITY, Config::CA_CERT));
          }

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

void PollbookClient::configure_ssl_context(asio::ssl::context& ssl_context, 
                           asio::ssl::stream<asio::ip::tcp::socket>& socket,
                           const std::string& cert_file, 
                           const std::string& key_file, 
                           const std::string& ca_file) {
    ssl_context.set_verify_mode(asio::ssl::verify_peer);
    ssl_context.load_verify_file(ca_file);
    SSL *ssl = socket.native_handle();
    if (!SSL_use_certificate_file(ssl, cert_file.c_str(), SSL_FILETYPE_PEM)) {
        // Handle error
        std::cout << "Error in cert" << std::endl;
    }
    if (!SSL_use_PrivateKey_file(ssl, key_file.c_str(), SSL_FILETYPE_PEM)) {
        // Handle error
        std::cout << "Error in Pkey" << std::endl;
    }
}

void PollbookClient::connect_checkin_server(const std::string& hostname, const std::string& port) {
    //asio::ip::tcp::resolver server_resolver(network_io_context);
    //auto resolve_results = server_resolver.resolve(hostname, port);
    //asio::connect(checkin_server_socket, resolve_results);
    PollbookClient::make_handshake(hostname, port, false);

    checkin_connected = true;
}

void PollbookClient::connect_id_server(const std::string& hostname, const std::string& port) {
    PollbookClient::make_handshake(hostname, port, true);
    id_connected = true;
}

void PollbookClient::make_handshake(const std::string& host, const std::string& port, bool is_id_server) {
    asio::ip::tcp::resolver resolver(network_io_context);
    auto endpoints = resolver.resolve(host, port);

    try {
        asio::ssl::stream<asio::ip::tcp::socket>& socket =
            is_id_server ? id_server_socket : checkin_server_socket;

        asio::connect(socket.lowest_layer(), endpoints);
        socket.handshake(asio::ssl::stream_base::client);

        // Extract SSL pointer
        SSL* ssl_native = socket.native_handle();

        // Get peer certificate
        X509* cert = SSL_get_peer_certificate(ssl_native);
        if(cert) {
            EVP_PKEY* pubkey = X509_get_pubkey(cert);
            if(pubkey) {
                // Get target file name from config
                std::string cert_path = Config::getString(
                    Config::SECTION_SECURITY,
                    is_id_server ? Config::ID_SERVICE_PUBLIC_KEY : Config::CHECKIN_SERVICE_PUBLIC_KEY);

                FILE* fp = fopen(cert_path.c_str(), "w");
                if(fp) {
                    PEM_write_PUBKEY(fp, pubkey);
                    fclose(fp);
                } else {
                    std::cerr << "Failed to open cert path: " << cert_path << "\n";
                }

                // Set verifier now that pubkey is saved
                openssl::EnvelopeKey verifier_key = openssl::EnvelopeKey::from_pem_public(cert_path);
                if(is_id_server) {
                    // id_service_verifier= openssl::Verifier(verifier_key, openssl::DigestAlgorithm::SHA256);
                    // id_service_verifier = openssl::Verifier(std::move(verifier_key), openssl::DigestAlgorithm::SHA256);
                    id_service_verifier = std::make_unique<openssl::Verifier>(
                        openssl::EnvelopeKey::from_pem_public(cert_path),
                        openssl::DigestAlgorithm::SHA256);
                } else {
                    // checkin_service_verifier(verifier_key, openssl::DigestAlgorithm::SHA256);
                    checkin_service_verifier = std::make_unique<openssl::Verifier>(
                        openssl::EnvelopeKey::from_pem_public(cert_path),
                        openssl::DigestAlgorithm::SHA256);
                }

                EVP_PKEY_free(pubkey);
            } else {
                std::cerr << "Could not extract public key from certificate.\n";
            }
            X509_free(cert);
        } else {
            std::cerr << "No certificate received from peer\n";
        }

    } catch(const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        throw;
    }
}

void PollbookClient::start_id_request_write(std::uint64_t timestamp, std::string first_name, 
                                            std::string middle_name, std::string last_name, 
                                            const std::vector<std::uint8_t>& voter_id_data) {
    std::uint32_t my_id = Config::getUInt32(Config::SECTION_BASIC, Config::CLIENT_ID);
    VoterIDRequest::Body validation_request_body(
        my_id, timestamp, last_name, middle_name, 
        first_name, voter_id_data);
    // Sign the body of the message
    nlohmann::json body_json = VoterIDRequest::Body::ToJson(validation_request_body);
    std::string body_string = body_json.dump();
    private_key_signer.init();
    private_key_signer.add_bytes(body_string.data(), body_string.size());

    // Move the body into a full message, with the signature at the end
    VoterIDRequest validation_request(std::move(validation_request_body), private_key_signer.finalize()); 

    // Serialize and send the message
    nlohmann::json validation_json = VoterIDRequest::ToJson(validation_request);
    std::string response_message_string = validation_json.dump();
    std::size_t message_size = response_message_string.size();
    std::string buf = std::to_string(message_size) + "\n" + response_message_string + "\n";

    asio::async_write(id_server_socket,
        asio::buffer(buf),
        [this](const asio::error_code& error, std::size_t bytes_written) {
            if(!error) {
                logger->debug("Sent {} bytes to id server", bytes_written);
                logger->debug("Sent a request to verify the voter's ID to the ID service.");
                // After sending the request, start waiting for the response, which will start with a "size" header
                start_message_read(true);
            } else {
                logger->error("Error writing the ID-verification request to the ID service! Error: {}", error.message());
                current_request_promise.set_value({false, "Network error: I/O error when sending a request to the Voter ID service"});
            }
        });
}

void PollbookClient::start_message_read(bool on_id_server) {
    std::shared_ptr<std::size_t> message_size = std::make_shared<std::size_t>();
    auto buf = std::make_shared<asio::streambuf>();
    auto msg = std::make_shared<std::string>();
    if(on_id_server) {
        asio::async_read_until(id_server_socket, *buf, "\n",
        [this, msg, buf, message_size](const asio::error_code& error, std::size_t bytes_read) {
            if (!error) {
                logger->debug("Read {} bytes from socket into a std::size_t", bytes_read);
                *msg = std::string(asio::buffer_cast<const char*>(buf->data()), bytes_read);
                std::string json_string = *msg;
                nlohmann::json response_json = nlohmann::json::parse(json_string);
                VerifiedVoterID response = VerifiedVoterID::FromJson(response_json);
                *message_size = json_string.size();
                logger->debug("Message received from ID service, size {} bytes", *message_size);
                buf->consume(bytes_read);
                handle_id_response(response); 
            } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
                logger->error("ID service disconnected before sending message size");
                current_request_promise.set_value({false, "Network error: Voter ID service disconnected"});
            } else {
                logger->error("Unexpected error when reading message size from ID service: {}", error.message());
                current_request_promise.set_value({false, "Network error: I/O error when reading from Voter ID service"});
            }
        });
    } else {
        asio::async_read_until(checkin_server_socket, *buf, "\n",
        [this, buf, message_size](const asio::error_code& error, std::size_t bytes_read) {
            if (!error) {
                logger->debug("Read {} bytes from socket into a std::size_t", bytes_read);
                std::string full_buffer = std::string(asio::buffer_cast<const char*>(buf->data()), bytes_read);
                std::stringstream ss(full_buffer);
                ss >> *message_size;
                buf->consume(bytes_read);
                logger->debug("Message received from checkin service, size {} bytes", *message_size);
                start_checkin_response_read(*message_size, buf);
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

void PollbookClient::handle_id_response(const VerifiedVoterID& response) {
    // Verify the signature, then asynchronously schedule a write for the check-in request
    nlohmann::json response_json;
    response_json["presented_id"] = VoterIDRequest::ToJson(response.presented_id);
    response_json["voter_unique_id"] = response.voter_unique_id;

    std::string response_str = response_json.dump();

    id_service_verifier->init();
    id_service_verifier->add_bytes(response_str.data(), response_str.size());
    /* id_service_verifier.add_bytes(&response.voter_unique_id, sizeof(response.voter_unique_id)); */
    bool verified = id_service_verifier->finalize(response.id_service_signature);
    if(verified) {
        start_checkin_request_write(response);
    } else {
        current_request_promise.set_value({false, "Invalid signature from the ID verification service on the voter's ID. OpenSSL error: " +
                                                      openssl::get_error_string(ERR_get_error(), "")});
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
                                      verified_id_response.voter_unique_id, verified_id_response);
    // Serialize the body of the message and sign the bytes
    std::string request_body_str = CheckinRequest::Body::ToJson(request_body).dump();
    private_key_signer.init();
    private_key_signer.add_bytes(request_body_str.data(), request_body_str.size());
    // Construct the message, with the signature at the end
    CheckinRequest request(std::move(request_body), private_key_signer.finalize());

    // Serialize and send the message 
    nlohmann::json request_json = CheckinRequest::ToJson(request);
    std::string request_message_string = request_json.dump();
    std::size_t message_size = request_message_string.size();
    std::string buffer = std::to_string(message_size) + "\n" + request_message_string +"\n";

    asio::async_write(checkin_server_socket,
        asio::buffer(buffer),
        [this](const asio::error_code& error, std::size_t bytes_written) {
            if(!error) {
                logger->debug("Sent a check-in request for voter {} {} {} to check-in service.", std::get<0>(current_request_voter_name), std::get<1>(current_request_voter_name), std::get<2>(current_request_voter_name));
                start_message_read(false);
            } else {
                logger->error("Error writing the ID-verification request to the ID service! Error: {}", error.message());
                current_request_promise.set_value({false, "Network error: I/O error when sending a request to the check-in service"});
            }
        });
}

void PollbookClient::start_checkin_response_read(std::size_t message_size, std::shared_ptr<asio::streambuf> buf) {
    checkin_server_buffer.resize(message_size);

    asio::async_read_until(checkin_server_socket, *buf, "\n",
            [this, buf](const asio::error_code& error, std::size_t bytes_read) {
                if (!error) {
                    std::string full_buffer = std::string(asio::buffer_cast<const char*>(buf->data()), bytes_read);

                    buf->consume(bytes_read);
                    nlohmann::json response_json = nlohmann::json::parse(full_buffer);
                    CheckinResponse response = CheckinResponse::FromJson(response_json);
                    handle_checkin_response(response);
                } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
                    logger->error("Checkin service disconnected before sending message size");
                    current_request_promise.set_value({false, "Network error: Checkin service disconnected"});
                } else {
                    logger->error("Unexpected error when reading message size from checkin service: {}", error.message());
                    current_request_promise.set_value({false, "Network error: I/O error when reading from the checkin service"});
                }

            });
}

void PollbookClient::handle_checkin_response(const CheckinResponse& response) {
    // Serialize the body of the response to verify the signature
    std::string response_body_str = CheckinResponse::Body::ToJson(response.body).dump();
    checkin_service_verifier->init();
    checkin_service_verifier->add_bytes(response_body_str.data(), response_body_str.size());
    bool verified = checkin_service_verifier->finalize(response.checkin_service_signature);
    if(!verified) {
        current_request_promise.set_value({false, "Invalid signature on check-in service's response. OpenSSL error: " +
                                                      openssl::get_error_string(ERR_get_error(), "")});
    } else if(response.body.approved) {
        logger->debug("Checkin service Ticket: {}", response.body.ticket);
        current_request_promise.set_value({true, ""});
    } else {
        current_request_promise.set_value({false, "Check-in service rejected the request"});
    }
}

std::future<CheckinResult> PollbookClient::check_in_voter(const std::string& first_name, const std::string& middle_name,
                                                          const std::string& last_name,
                                                          std::uint32_t desired_voter_unique_id,
                                                          const std::vector<std::uint8_t>& voter_id_data) {

    // Prepend the desired voter unique ID at the beginning of the voter ID data, to tell our
    // dummy voter ID service what unique ID it should "match" the data to
    std::vector<std::uint8_t> id_data_with_number(voter_id_data.size() + sizeof(std::uint32_t));
    std::memcpy(id_data_with_number.data(), &desired_voter_unique_id, sizeof(std::uint32_t));
    std::memcpy(id_data_with_number.data() + sizeof(std::uint32_t), voter_id_data.data(), voter_id_data.size());

    return check_in_voter(first_name, middle_name, last_name, id_data_with_number);
}

std::future<CheckinResult> PollbookClient::check_in_voter(const std::string& first_name, const std::string& middle_name,
                                                          const std::string& last_name, const std::vector<std::uint8_t>& voter_id_data) {
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
    // Start the checkin process by asynchronously scheduling the write of the ID-verification request
    start_id_request_write(current_timestamp, first_name, middle_name, last_name, voter_id_data);
    // Return a future that the caller can use to wait for the process to finish
    return current_request_promise.get_future();
}

std::future<CheckinResult> PollbookClient::verify_ticket(const std::string& ticket, const std::uint32_t pin) {
    if(!checkin_connected) {
        throw std::runtime_error("Client must be connected before calling check_in_voter!");
    }
    // Reset the promise-future pair for the current request
    current_request_promise = std::promise<CheckinResult>();

    auto current_time = std::chrono::system_clock::now();
    std::uint64_t current_timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                                          current_time.time_since_epoch())
                                          .count();
    std::uint32_t client_id = Config::getUInt32(Config::SECTION_BASIC, Config::CLIENT_ID);
    TicketRequest::Body response_body(client_id, current_timestamp, ticket, pin);
    nlohmann::json body_json = TicketRequest::Body::ToJson(response_body);
    std::string body_string = body_json.dump();
    private_key_signer.init();
    private_key_signer.add_bytes(body_string.data(), body_string.size());
    TicketRequest request(std::move(response_body), private_key_signer.finalize());

    nlohmann::json request_json = TicketRequest::ToJson(request);
    std::string message = request_json.dump();

    std::size_t message_size = message.size();
    std::string outgoing_message = std::to_string(message_size) + "\n" + message + "\n";

    // Send the message asynchronously
    asio::async_write(checkin_server_socket, asio::buffer(outgoing_message),
        [this](const asio::error_code& error, std::size_t /*bytes_transferred*/) {
            if (!error) {
                logger->debug("Sent verify_ticket request to check-in service.");
                start_verify_ticket_response_read();
            } else {
                logger->error("Error writing the verify_ticket request to the check-in service! Error: {}", error.message());
                current_request_promise.set_value({false, "Network error: I/O error when sending a verify_ticket request to the check-in service"});
            }
        });

    // Return a future that the caller can use to wait for the process to finish
    return current_request_promise.get_future();
}

void PollbookClient::start_verify_ticket_response_read() {
    auto buf = std::make_shared<asio::streambuf>();
    
    asio::async_read_until(checkin_server_socket, *buf, "\n",
        [this, buf](const asio::error_code& error, std::size_t bytes_read) {
            if (!error) {
                std::string response_str(asio::buffer_cast<const char*>(buf->data()), bytes_read);
                buf->consume(bytes_read);
                
                try {
                    std::string first_name, middle_name, last_name;
                    nlohmann::json response_json = nlohmann::json::parse(response_str);
                    TicketResponse response = TicketResponse::FromJson(response_json);

                    std::string response_body_str = TicketResponse::Body::ToJson(response.body).dump();
                    checkin_service_verifier->init();
                    checkin_service_verifier->add_bytes(response_body_str.data(), response_body_str.size());
                    bool verified = checkin_service_verifier->finalize(response.signature);

                    bool is_valid = response_json["body"]["approved"];
                    std::string secret = response_json["body"]["secret"];
                    first_name = response_json["body"]["first_name"];
                    middle_name = response_json["body"]["middle_name"];
                    last_name = response_json["body"]["last_name"];
                    if(verified) {

                        if (is_valid) {
                            logger->debug("Voter verified. Hello {} {} {}! Secret: {}", first_name, middle_name, last_name, secret);
                            current_request_promise.set_value({true, secret});
                        } else {
                            current_request_promise.set_value({false, secret});
                        }
                    } else {
                        current_request_promise.set_value({false, "Invalid signature from the ID verification service on the voter's ID. OpenSSL error: " +
                                                                    openssl::get_error_string(ERR_get_error(), "")});
                    }
                } catch (const std::exception& e) {
                    logger->error("Error parsing verify_ticket response: {}", e.what());
                    current_request_promise.set_value({false, "Error parsing server response"});
                }
            } else {
                logger->error("Error reading verify_ticket response: {}", error.message());
                current_request_promise.set_value({false, "Network error: I/O error when reading verify_ticket response from the check-in service"});
            }
        });
}

void PollbookClient::send_string_message(const std::string& message) {
    if(!checkin_connected) {
        throw std::runtime_error("Client must be connected before calling send_string_message!");
    }
    nlohmann::json j;
    j["ticket"] = std::string(message);
    std::size_t message_size = message.size();
    std::string outgoing_message = std::to_string(message_size) + "\n" + message + "\n";
    asio::write(checkin_server_socket, asio::buffer(outgoing_message));
    // asio::async_read_until(checkin_server_socket, );
}

std::string PollbookClient::receive_string_message() {
    asio::streambuf receive_buffer;
    asio::error_code error;

    asio::read_until(checkin_server_socket, receive_buffer, '\n', error);
    logger->debug("reading works");

    if (error) {
        throw std::runtime_error("Error receiving message: " + error.message());
    }

    std::string line;
    std::istream is(&receive_buffer);
    std::getline(is, line);
    std::cout << line;

    return line;
}

}  // namespace epollbook
