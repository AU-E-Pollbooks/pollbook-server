#include "epollbook/checkin_service.hpp"
#include "epollbook/config/config.hpp"
#include "epollbook/log_utils.hpp"

#include <spdlog/fmt/ostr.h>
#include <asio.hpp>

#include <array>
#include <iostream>

namespace epollbook {

CheckinService::CheckinService()
    : logger(spdlog::get(LogUtils::get_default_logger_name())),
      connection_listener(network_io_context,
                          asio::ip::tcp::endpoint(
                              asio::ip::tcp::tcp::v4(),
                              Config::getUInt16(Config::SECTION_BASIC, Config::CHECKIN_SERVICE_PORT))) {}

void CheckinService::do_accept() {
    connection_listener.async_accept(network_io_context,
                                     [this](const asio::error_code& error, asio::ip::tcp::socket peer) {
                                         handle_accept(error, std::move(peer));
                                     });
}

void CheckinService::handle_accept(const asio::error_code& error, asio::ip::tcp::socket new_socket) {
    asio::ip::tcp::endpoint client_ip = new_socket.remote_endpoint();
    logger->debug("Accepted a connection from client at {}", client_ip);
    // Put the new socket in the map
    client_sockets.emplace(client_ip, std::move(new_socket));
    // Start a read for the message size
    start_size_read(client_ip);
    // Enqueue another accept operation for the connection listener so it keeps listening
    do_accept();
}

void CheckinService::start_size_read(asio::ip::tcp::endpoint client_ip) {
    // Put this integer on the heap so it stays in memory after this method ends
    std::shared_ptr<std::size_t> message_size = std::make_shared<std::size_t>();
    // Make an asio "buffer" that points to the address of the integer and read 4 bytes into it
    asio::async_read(client_sockets.at(client_ip),
                     asio::buffer(&(*message_size), sizeof(std::size_t)),
                     [this, client_ip, message_size](const asio::error_code& error, std::size_t bytes_read) {
                         if(!error) {
                             logger->debug("Client at {}: Message size is {} bytes", client_ip, message_size);
                             start_body_read(client_ip, *message_size);
                         } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
                             logger->debug("Client at {} disconnected before sending message size", client_ip);
                             client_sockets.erase(client_ip);
                         }
                     });
}

void CheckinService::start_body_read(const asio::ip::tcp::endpoint& client_ip, std::size_t size_of_message) {
    // Allocate a buffer for the message
    client_receive_buffers.emplace(client_ip, std::vector<uint8_t>(size_of_message));
    // Asynchronously read until it is full
    asio::async_read(client_sockets.at(client_ip),
                     asio::buffer(client_receive_buffers.at(client_ip)),
                     [this, client_ip](const asio::error_code& error, std::size_t bytes_transferred) {
                         handle_read(client_ip, error, bytes_transferred);
                     });
}

void CheckinService::handle_read(const asio::ip::tcp::endpoint& client_ip, const asio::error_code& error, std::size_t bytes_transferred) {
    if(!error) {
        // For now, just assume the message was a string (sent as a char array), and print it out
        logger->debug("Finished reading message of size {} from client at {}", client_receive_buffers.at(client_ip).size(), client_ip);
        std::string message_string(reinterpret_cast<const char*>(client_receive_buffers.at(client_ip).data()),
                                   client_receive_buffers.at(client_ip).size());
        std::cout << "Message from " << client_ip << ": " << message_string << std::endl;
    } else if(error == asio::error::eof || error == asio::error::connection_aborted) {
        logger->debug("Client at {} disconnected before sending entire message", client_ip);
    }
}

void CheckinService::run() {
    // Post the first asynchronous accept
    do_accept();
    network_io_context.run();
}

}  // namespace epollbook