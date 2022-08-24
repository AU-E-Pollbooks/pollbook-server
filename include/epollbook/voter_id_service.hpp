#pragma once

#include "openssl/envelope_key.hpp"
#include "openssl/signature.hpp"
#include "voter_id_request.hpp"

#include <spdlog/spdlog.h>
#include <asio.hpp>

#include <cstdint>
#include <map>
#include <vector>

namespace epollbook {


/**
 * A server class that provides a very simple "voter ID validation" service.
 * This is not intended to be production quality; it's just here to facilitate
 * testing the other parts of the check-in service.
 */
class VoterIDService {
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
     * The Signer object the server uses to sign messages, which is configured
     * with the service's signing key.
     */
    openssl::Signer signer;
    /**
     * Maps a client IP address to a Verifier initialized with that client's
     * public key.
     */
    std::map<asio::ip::tcp::endpoint, openssl::Verifier> client_verifiers;
    /**
     * Handler function for ASIO accept events.
     */
    void handle_accept(const asio::error_code& error, asio::ip::tcp::socket incoming_socket);
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
    void start_body_read(const asio::ip::tcp::endpoint& client_ip, std::size_t size_of_message);

    /**
     * Handles an asynchronous read event for a message from a client. When ASIO
     * calls this function, the receive buffer for that client should be populated
     * with message data.
     */
    void handle_read(const asio::ip::tcp::endpoint& client_ip, const asio::error_code& error, std::size_t bytes_read);

    /**
     * Handles a single ID-validation request from a client, assuming it has already
     * been read and deserialized in the "raw" read handler.
     */
    void handle_validation_request(const asio::ip::tcp::endpoint& client_ip, const VoterIDRequest& request);

    /**
     * Examines the binary data provided by a client to represent a voter's ID
     * and determines if it is valid. Right now this does nothing because we
     * don't know any details of how voter IDs are represented, stored, or validated;
     * it's just here as a placeholder.
     *
     * @param id_data The voter ID data provided by an ID validation request
     * @return True if the ID is valid, false if it is not
     */
    bool validate_id_data(const std::vector<uint8_t>& id_data);

public:
    /**
     * The interval, in milliseconds, within which voter ID verification
     * requests will be considered fresh enough to sign; in the future
     * this should be set from a configuration file.
     */
    const int request_freshness_interval = 5000;
    /**
     * Constructor; configures the service to run on the specified port, and
     * loads the private key it will use to sign messages from the specified
     * file.
     *
     * @param port The port the Voter ID service should listen on for incoming
     * requests.
     * @param private_key_filename The name/path to a PEM file containing the
     * server's private key.
     */
    VoterIDService(std::uint16_t port, const std::string& private_key_filename);

    /**
     * Starts the service. This function gives control of the calling thread to
     * the ASIO io_context to start waiting for client connections, so callers
     * should expect it to block forever.
     */
    void run();
};

}  // namespace epollbook