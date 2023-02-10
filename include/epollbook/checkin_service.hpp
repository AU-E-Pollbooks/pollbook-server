#pragma once

#include "checkin_request.hpp"
#include "openssl/signature.hpp"

#include <spdlog/spdlog.h>
#include <asio.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

namespace epollbook {

class CheckinService {
public:
    /**
     * The hash (digest) algorithm that will be used by this service for
     * computing and verifying signatures. SHA256 is a common standard, so this
     * shouldn't be surprising or need to be changed.
     */
    const openssl::DigestAlgorithm signature_digest_algorithm = openssl::DigestAlgorithm::SHA256;
private:
    /** A pointer to the debug logger */
    std::shared_ptr<spdlog::logger> logger;
    /** The io_context that all the sockets will use */
    asio::io_context network_io_context;
    /**
     * A "server socket" that listens for incoming connections from clients
     */
    asio::ip::tcp::acceptor connection_listener;
    /**
     * Maps a client IP address to a socket connected to that client
     */
    std::map<asio::ip::tcp::endpoint, asio::ip::tcp::socket> client_sockets;
    /**
     * Maps a client IP address to a byte buffer currently being used to
     * receive a message from that client.
     */
    std::map<asio::ip::tcp::endpoint, std::vector<uint8_t>> client_receive_buffers;
    /**
     * Maps a client's unique ID to a Verifier initialized with that client's
     * public key.
     */
    std::map<std::uint32_t, openssl::Verifier> client_verifiers;
    /**
     * A Verifier object configured with the public key of the ID-verification
     * service.
     */
    openssl::Verifier id_service_verifier;
    /**
     * The Signer object the server uses to sign messages, which is configured
     * with the service's signing key.
     */
    openssl::Signer signer;

    /**
     * Handler function for ASIO accept events.
     */
    void handle_accept(const asio::error_code& error, asio::ip::tcp::socket incoming_socket);

    /**
     * Handles an asynchronous read event for a message from a client. When ASIO
     * calls this function, the receive buffer for that client should be populated
     * with message data.
     */
    void handle_read(const asio::ip::tcp::endpoint& client_ip, const asio::error_code& error, std::size_t bytes_read);

    /**
     * Starts an asynchronous accept request on the connection listener.
     */
    void do_accept();

    /**
     * Starts an asynchronous read on the socket for the specified client
     * that will attempt to read sizeof(std::size_t) bytes. This is the size
     * of the remaining message, and needs to be read first to determine the
     * size of the buffer to allocate.
     */
    void start_size_read(asio::ip::tcp::endpoint client_ip);

    /**
     * Starts an asynchronous read on the socket for the specified client,
     * which will read the specified number of bytes. Assumes the server has
     * already read the initial 4 bytes to determine the size of the message.
     */
    void start_payload_read(const asio::ip::tcp::endpoint& client_ip, std::size_t size_of_message);

    /**
     * Handles a single check-in request from a client, assuming it has already
     * been read from a socket and deserialized. Called from the completion handler
     * of the read initiated by start_payload_read().
     * @param client_ip The IP address of the client that sent the request
     * @param request The deserialized CheckinRequest object containing the client's message
     */
    void handle_checkin_request(const asio::ip::tcp::endpoint& client_ip, const CheckinRequest& request);

    /**
     * Loads a public key for a particular client from the PEM file that should
     * correspond to a client with that ID, based on the configuration options
     * client_keys_folder and client_key_file_prefix.
     *
     * @param client_id The numeric ID of the client
     * @return true If the client's public key was loaded successfully, false
     * if it was not found in the expected location
     */
    bool load_client_public_key(std::uint32_t client_id);

public:
    /**
     * Constructs the service
     */
    CheckinService();
    /**
     * Starts the service. This function gives control of the calling thread to
     * the ASIO io_context to start waiting for client connections, so callers
     * should expect it to block forever.
     */
    void run();
};

}  // namespace epollbook