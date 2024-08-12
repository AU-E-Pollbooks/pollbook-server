#include "epollbook/voter_id_service.hpp"
#include "epollbook/config/config.hpp"
#include "epollbook/log_utils.hpp"

#include <spdlog/fmt/ostr.h>
#include <asio.hpp>
#include <asio/ssl.hpp>

#include <array>
#include <chrono>
#include <cmath>
#include <iostream>
#include <sstream>

namespace epollbook {

VoterIDService::VoterIDService()
        : logger(spdlog::get(LogUtils::get_default_logger_name())),
          ssl_context(asio::ssl::context::tlsv12_server),
          connection_listener(
                  network_io_context,
                  asio::ip::tcp::endpoint(
                      asio::ip::tcp::tcp::v4(),
                      Config::getUInt16(Config::SECTION_BASIC, Config::ID_SERVICE_PORT))),
          signer(openssl::EnvelopeKey::from_pem_private(Config::getString(Config::SECTION_SECURITY, Config::LOCAL_PRIVATE_KEY)),
                 signature_digest_algorithm) {
          configure_ssl_context(ssl_context,
                      Config::getString(Config::SECTION_SECURITY, Config::ID_SERVICE_CERT),
                      Config::getString(Config::SECTION_SECURITY, Config::LOCAL_PRIVATE_KEY),
                      Config::getString(Config::SECTION_SECURITY, Config::CA_CERT));
}

void VoterIDService::do_accept() {
    connection_listener.async_accept(
            network_io_context,
            [this](const asio::error_code& error, asio::ip::tcp::socket peer) {
                handle_accept(error, std::move(peer));
            });
}

std::uint32_t VoterIDService::get_client_id_from_cert(X509* cert) {
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

void VoterIDService::handle_accept(const asio::error_code& error, asio::ip::tcp::socket new_socket) {
    if (!error) {
        /* auto ssl_stream = std::make_shared<asio::ssl::stream<asio::ip::tcp::socket>>(std::move(new_socket), ssl_context); */
        auto client_ip = new_socket.remote_endpoint();

        auto ssl_stream_ptr = std::make_shared<asio::ssl::stream<asio::ip::tcp::socket>>(std::move(new_socket), ssl_context);

        ssl_stream_ptr->async_handshake(asio::ssl::stream_base::server,
            [this, ssl_stream_ptr, client_ip](const asio::error_code& handshake_error) {
                if (!handshake_error) {
                    // The handshake was successful
                    // You can now read or write to the socket
                    /* asio::ip::tcp::endpoint client_ip = new_socket.remote_endpoint(); */
                    /* auto client_ip = ssl_stream_ptr->lowest_layer().remote_endpoint(); */
                    X509* clientCert = SSL_get0_peer_certificate(ssl_stream_ptr->native_handle());

                    if (clientCert != nullptr) {
                        std::uint32_t client_id = get_client_id_from_cert(clientCert);
                        // Extract the public key from the certificate
                        EVP_PKEY* pubkey = X509_get_pubkey(clientCert);
                        if (pubkey != nullptr) {
                            // Open a file to write the public key
                            save_pub_key(pubkey, client_id);
                            // Clean up
                            EVP_PKEY_free(pubkey);
                        } else {
                            std::cerr << "Error extracting public key" << std::endl;
                        }
                        // Clean up
                        X509_free(clientCert);
                    } else {
                        std::cerr << "No certificate received from client" << std::endl;
                    }
                    client_ssl_streams[client_ip] = ssl_stream_ptr;

                    logger->debug("Accepted a connection from client at {}", client_ip);
                    // Put the new socket in the map
                    /* client_sockets.emplace(client_ip, ssl_stream_ptr); */
                    // Start a read for the message size
                    start_size_read(client_ip);
                }
                else {
                    logger->warn("Handshake failed: {}", handshake_error.message());
                }
                // Enqueue another accept operation for the connection listener so it keeps listening
                do_accept();
            });
    }
    else {
        logger->warn("Connection failed: {}", error.message());
    }
}

void VoterIDService::configure_ssl_context(asio::ssl::context& ssl_context,
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

void VoterIDService::start_size_read(asio::ip::tcp::endpoint client_ip) {
    std::shared_ptr<std::size_t> message_size = std::make_shared<std::size_t>();
    auto msg_size_str = std::make_shared<std::string>();
    /* auto ssl_stream = client_ssl_streams[client_ip]; */
    if (client_buffers.find(client_ip) == client_buffers.end()) {
        client_buffers[client_ip] = std::make_shared<asio::streambuf>();
    }
    asio::async_read_until(*(client_ssl_streams.at(client_ip)), *client_buffers[client_ip], "\n",
    [this, client_ip, message_size, msg_size_str](const asio::error_code& error, std::size_t bytes_read) {
        if(!error) {
            *msg_size_str = std::string(asio::buffer_cast<const char*>(this->client_buffers[client_ip]->data()), bytes_read);
            *message_size = std::stoul(*msg_size_str);
            logger->debug("Client at {}: Message size is {} bytes", client_ip, *message_size);
            client_buffers[client_ip]->consume(bytes_read);
            start_payload_read(client_ip, *message_size);
        } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
            logger->debug("Client at {} disconnected before sending message size", client_ip);
            client_ssl_streams.erase(client_ip);
        }
    });
}

void VoterIDService::start_payload_read(asio::ip::tcp::endpoint client_ip, std::size_t size_of_message) {
    auto msg = std::make_shared<std::string>();
    if (client_buffers.find(client_ip) == client_buffers.end()) {
        client_buffers[client_ip] = std::make_shared<asio::streambuf>();
    }
    asio::async_read_until(*(client_ssl_streams.at(client_ip)), *client_buffers[client_ip], "\n",
    [this, msg, client_ip, size_of_message](const asio::error_code& error, std::size_t bytes_read) {
        if(!error) {
            if(size_of_message == bytes_read - 1) {
                *msg = std::string(asio::buffer_cast<const char*>(this->client_buffers[client_ip]->data()), bytes_read);
                std::string json_string = *msg;
                client_buffers[client_ip]->consume(bytes_read);
                logger->debug("Finished reading message of size {} from client at {}", bytes_read, client_ip);

                nlohmann::json json = nlohmann::json::parse(json_string);
                VoterIDRequest request = VoterIDRequest::FromJson(json);
                handle_validation_request(client_ip, request);
            } else {
                logger->warn("Size of the message does not match the size that is received from the server for the client {}", client_ip);
                client_ssl_streams.erase(client_ip);
            }
        } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
            logger->debug("Client at {} disconnected before sending entire message", client_ip);
            client_ssl_streams.erase(client_ip);
        } else {
            logger->warn("Unexpected I/O error when reading a request message from client {}. Error: {}", client_ip, error.message());
        }

    });
}

void VoterIDService::save_pub_key(EVP_PKEY* pubkey, std::uint32_t client_id) {
    std::stringstream pub_key_file_path_builder;
    pub_key_file_path_builder << Config::getString(Config::SECTION_SECURITY, Config::CLIENT_KEYS_FOLDER)
                          << Config::getString(Config::SECTION_SECURITY, Config::CLIENT_KEY_FILE_PREFIX) << client_id << ".pem";
    std::string pkey_file_path = pub_key_file_path_builder.str();
    FILE* pubkey_file = fopen(pkey_file_path.c_str(), "w");
    if (pubkey_file != nullptr) {
        // Write the public key in PEM format
        PEM_write_PUBKEY(pubkey_file, pubkey);
        fclose(pubkey_file);
        logger->debug("Saved public key for client {} to file {}", client_id, pkey_file_path);
    } else {
        logger->error("Error opening file {} to write public key", pkey_file_path);
    }
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
    std::uint32_t voter_unique_id = validate_and_match_id_data(request.body.voter_id_data);
    if(voter_unique_id == INVALID_VOTER_ID) {
        logger->warn("Rejected a voter ID validation request because the ID data was not valid.");
        return;
    }
    // Ensure the public key for this client is in memory
    if(client_verifiers.find(request.body.client_id_num) == client_verifiers.end()) {
        //Below we put public key into client keys folder to be able to verify later

        if(!load_client_public_key(request.body.client_id_num)) {
            logger->warn("Could not load the public key for client number {}. Ignoring a voter ID validation request.", request.body.client_id_num);
            return;
        }
    }
    // Validate the client's signature
    nlohmann::json request_body_json = VoterIDRequest::Body::ToJson(request.body);
    std::string request_body_string = request_body_json.dump();
    openssl::Verifier& verifier = client_verifiers.at(request.body.client_id_num);
    verifier.init();
    verifier.add_bytes(request_body_string.data(), request_body_string.size());

    if(!verifier.finalize(request.client_signature)) {
        logger->warn("Rejected a voter ID validation request because the client's signature was invalid.");
        return;
    }
    logger->info("Approved a voter ID validation request from client #{} at {}, voter's UID is {}", request.body.client_id_num, client_ip, voter_unique_id);

    // Sign the validation request and the unique voter ID
    // The request was already serialized, in the receive buffer, so there's no need to serialize it again
    nlohmann::json body_json;
    body_json["presented_id"] = VoterIDRequest::ToJson(request);
    body_json["voter_unique_id"] = voter_unique_id;
    std::string request_body_str = body_json.dump();
    signer.init();
    signer.add_bytes(request_body_str.data(), request_body_str.size());
    std::vector<std::uint8_t> signature = signer.finalize();
    // Send it back in a response. For now, the write is synchronous, since we don't expect it to take very long.
    VerifiedVoterID response(request, voter_unique_id, std::move(signature));

    //
    nlohmann::json response_json = VerifiedVoterID::ToJson(response);

    std::size_t response_size = response_json.size();
    std::string response_msg_str = response_json.dump();
    std::string buffer = response_msg_str + "\n";

    logger->debug("Sending a response of size {} to client at {}", response_size, client_ip);
    asio::write(*(client_ssl_streams.at(client_ip)), asio::buffer(buffer));
}

std::uint32_t VoterIDService::validate_and_match_id_data(const std::vector<std::uint8_t>& id_data) {
    std::uint32_t desired_id_number;
    std::memcpy(&desired_id_number, id_data.data(), sizeof(std::uint32_t));
    return desired_id_number;
}

bool VoterIDService::load_client_public_key(std::uint32_t client_id) {
    std::stringstream key_file_path_builder;
    key_file_path_builder << Config::getString(Config::SECTION_SECURITY, Config::CLIENT_KEYS_FOLDER)
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
    logger->info("ID Service started on port {}", Config::getUInt16(Config::SECTION_BASIC, Config::ID_SERVICE_PORT));
    network_io_context.run();
}

}  // namespace epollbook
