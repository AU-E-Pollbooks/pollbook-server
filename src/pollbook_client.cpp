#include "epollbook/pollbook_client.hpp"
#include "epollbook/config/config.hpp"
#include "epollbook/openssl/signature.hpp"

#include <asio.hpp>

#include <cstring>
#include <stdexcept>
#include <vector>

namespace epollbook {

PollbookClient::PollbookClient()
    : checkin_server_socket(network_io_context),
      id_server_socket(network_io_context),
      checkin_connected(false),
      id_connected(false),
      private_key_signer(openssl::EnvelopeKey::from_pem_private(
                             Config::getString(Config::SECTION_SECURITY, Config::LOCAL_PRIVATE_KEY)),
                         openssl::DigestAlgorithm::SHA256) {}

void PollbookClient::connect() {
    connect_checkin_server(Config::getString(Config::SECTION_BASIC, Config::CHECKIN_SERVICE_HOST),
                           Config::getString(Config::SECTION_BASIC, Config::CHECKIN_SERVICE_PORT));
    connect_id_server(Config::getString(Config::SECTION_BASIC, Config::ID_SERVICE_HOST),
                      Config::getString(Config::SECTION_BASIC, Config::ID_SERVICE_PORT));
}

void PollbookClient::connect_checkin_server(const std::string& hostname, const std::string& port) {
    asio::ip::tcp::resolver server_resolver(network_io_context);
    auto resolve_results = server_resolver.resolve(hostname, port);
    asio::connect(checkin_server_socket, resolve_results);
    checkin_connected = true;
}

void PollbookClient::connect_id_server(const std::string& hostname, const std::string& port) {
    asio::ip::tcp::resolver server_resolver(network_io_context);
    auto resolve_results = server_resolver.resolve(hostname, port);
    asio::connect(id_server_socket, resolve_results);
    id_connected = true;
}

void PollbookClient::send_string_message(const std::string& message) {
    if(!checkin_connected) {
        throw std::runtime_error("Client must be connected before calling send_string_message!");
    }
    // Message format: Length of the message in bytes, then body of the message
    std::vector<uint8_t> outgoing_message_buffer(sizeof(std::size_t) + message.size());
    std::size_t message_size = message.size();
    std::memcpy(outgoing_message_buffer.data(), &message_size, sizeof(message_size));
    std::memcpy(outgoing_message_buffer.data() + sizeof(message_size), message.data(), message_size);
    asio::write(checkin_server_socket, asio::buffer(outgoing_message_buffer));
}

}  // namespace epollbook
