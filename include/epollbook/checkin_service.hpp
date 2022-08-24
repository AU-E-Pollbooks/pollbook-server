#pragma once

#include <spdlog/spdlog.h>
#include <asio.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

namespace epollbook {

class CheckinService {
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
    void start_body_read(const asio::ip::tcp::endpoint& client_ip, std::size_t size_of_message);

public:
    /**
     * Constructor; configures the service to run on the specified TCP port.
     * (In the future this should probably be handled with a config file.)
     */
    CheckinService(std::uint16_t port);
    /**
     * Starts the service. This function gives control of the calling thread to
     * the ASIO io_context to start waiting for client connections, so callers
     * should expect it to block forever.
     */
    void run();
};

}  // namespace epollbook