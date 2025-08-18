#include <asio.hpp>
#include <iostream>
#include <string>

void send_command(asio::ip::tcp::socket& socket, const std::string& cmd) {
    std::string full_cmd = cmd + "\n";
    asio::write(socket, asio::buffer(full_cmd));
    asio::error_code ec;

    asio::streambuf buf;
    asio::read_until(socket, buf, '\n', ec);
    if (ec && ec != asio::error::eof) {
        throw asio::system_error(ec);
    }

    std::istream is(&buf);
    std::string response;
    std::getline(is, response);

    std::cout << "Server: " << response << std::endl;
}

int main() {
    try {
        asio::io_context io_context;
        asio::ip::tcp::resolver resolver(io_context);
        asio::ip::tcp::socket socket(io_context);

        auto endpoints = resolver.resolve("127.0.0.1", "9000");
        asio::connect(socket, endpoints);

        std::cout << "Connected to log query server. Type 'get', 'clear', or 'exit'.\n";

        std::string line;
        while (true) {
            std::cout << "> ";
            if (!std::getline(std::cin, line)) break;

            if (line == "exit") break;

            if (line == "get") {
                send_command(socket, line = "get_warnings");
            } else if (line == "clear") {
                send_command(socket, line = "clear_warnings");
            } else if (line.rfind("remove_warning ", 0) == 0) {
                send_command(socket, line);
            } else {
                std::cout << "Unknown command.\n";
            }
        }

        socket.shutdown(asio::ip::tcp::socket::shutdown_both);
        socket.close();
    } catch (std::exception& e) {
        std::cerr << "REPL client error: " << e.what() << std::endl;
    }

    return 0;
}

