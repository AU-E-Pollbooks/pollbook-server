#include "epollbook/pollbook_client.hpp"

#include <asio.hpp>

#include <cstring>
#include <stdexcept>
#include <vector>

namespace epollbook {

PollbookClient::PollbookClient()
    : checkin_server_socket(network_io_context),
      is_connected(false) {}

void PollbookClient::connect(const std::string& hostname, const std::string& port) {
    asio::ip::tcp::resolver server_resolver(network_io_context);
    auto resolve_results = server_resolver.resolve(hostname, port);
    asio::connect(checkin_server_socket, resolve_results);
    is_connected = true;
}

void PollbookClient::send_string_message(const std::string& message) {
    if(!is_connected) {
        throw std::runtime_error("Client must be connected before calling send_string_message!");
    }
    // Message format: Length of the message in bytes, then body of the message
    outgoing_message_buffer = std::vector<uint8_t>(sizeof(std::size_t) + message.size());
    std::size_t message_size = message.size();
    std::memcpy(outgoing_message_buffer.data(), &message_size, sizeof(message_size));
    std::memcpy(outgoing_message_buffer.data() + sizeof(message_size), message.data(), message_size);
    asio::write(checkin_server_socket, asio::buffer(outgoing_message_buffer));
}

}  // namespace epollbook
