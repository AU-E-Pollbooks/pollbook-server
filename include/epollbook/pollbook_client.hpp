#pragma once

#include <asio.hpp>

namespace epollbook {

class PollbookClient {
private:
    /** The IO Context to use for all network actions */
    asio::io_context network_io_context;
    /** The socket to use to communicate with the check-in server */
    asio::ip::tcp::socket checkin_server_socket;
    /**
     * True if the client has been connected to a check-in server, false if
     * connect() has not yet been called.
     */
    bool is_connected;
    /**
     * A byte array containing an outgoing message currently being written to the
     * server socket, if a message is being sent.
     */
    std::vector<uint8_t> outgoing_message_buffer;
    /**
     * A byte array that will be allocated to receive a message from the server once
     * a read is initiated. Its size will be determined by the first sizeof(size_t)
     * bytes of the incoming message from the server.
     */
    std::vector<uint8_t> incoming_message_buffer;

public:
    PollbookClient();
    /**
     * Connects the client to a check-in server, identified by its hostname (which
     * could be just an IP address) and port. This is a blocking, synchronous method.
     */
    void connect(const std::string& server_hostname, const std::string& server_port);

    /**
     * A simple demo method that sends a string to the server. This is a blocking,
     * synchronous method.
     */
    void send_string_message(const std::string& message);

};

}