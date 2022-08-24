#pragma once

#include "openssl/signature.hpp"

#include <asio.hpp>

namespace epollbook {

class PollbookClient {
private:
    /** The IO Context to use for all network actions */
    asio::io_context network_io_context;
    /** The socket to use to communicate with the check-in server */
    asio::ip::tcp::socket checkin_server_socket;
    /** The socket used to communicate with the voter-ID server */
    asio::ip::tcp::socket id_server_socket;
    /**
     * True if the client has been connected to a check-in server, false if
     * connect_checkin_server() has not yet been called.
     */
    bool checkin_connected;
    /**
     * True if the client has been connected to an ID-verification server, false
     * if connect_id_server() has not yet been called.
     */
    bool id_connected;
    /**
     * A byte array that will be allocated to receive a message from the check-in
     * server once a read is initiated. Its size will be determined by the first
     * sizeof(size_t) bytes of the incoming message from the server.
     */
    std::vector<uint8_t> checkin_server_buffer;
    /**
     * A byte array that will be allocated to receive a message from the check-in
     * server once a read is initiated. Its size will be determined by the first
     * sizeof(size_t) bytes of the incoming message from the server.
     */
    std::vector<uint8_t> id_server_buffer;
    /**
     * A Signer object configured with this client's private key, which it will
     * use to sign outgoing messages.
     */
    openssl::Signer private_key_signer;

public:
    /**
     * Constructs a new PollbookClient that is not connected to any server.
     *
     * @param private_key_filename The name/path to a PEM file containing the
     * client's private key.
     */
    PollbookClient(const std::string& private_key_filename);
    /**
     * Connects the client to a check-in server, identified by its hostname (which
     * could be just an IP address) and port. This is a blocking, synchronous method.
     */
    void connect_checkin_server(const std::string& server_hostname, const std::string& server_port);

    /**
     * Connects the client to a voter-ID-verification server, identified by its
     * hostname and port. This method blocks until the server is connected.
     */
    void connect_id_server(const std::string& server_hostname, const std::string& server_port);

    /**
     * A simple demo method that sends a string to the server. This is a blocking,
     * synchronous method.
     */
    void send_string_message(const std::string& message);

};

}