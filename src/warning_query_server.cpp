#include "epollbook/log_utils.hpp"
#include "epollbook/warning_query_server.hpp"

#include <nlohmann/json.hpp>
#include <iostream>
#include <asio/read_until.hpp>
#include <asio/streambuf.hpp>
#include <asio/write.hpp>


namespace epollbook {

WarningQueryServer::WarningQueryServer(asio::io_context& io_context, unsigned short port)
    : acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), port)) {}

void WarningQueryServer::start_accept() {
    auto socket = std::make_shared<asio::ip::tcp::socket>(acceptor.get_executor());
    acceptor.async_accept(*socket, [this, socket](const asio::error_code& error) {
        handle_accept(socket, error);
    });
}

void WarningQueryServer::handle_accept(std::shared_ptr<asio::ip::tcp::socket> socket, 
                                        const asio::error_code& err) {
    if(!err) {
        handle_session(socket);
    }
    start_accept();
}
void WarningQueryServer::handle_session(std::shared_ptr<asio::ip::tcp::socket> socket) {
    auto buf = std::make_shared<asio::streambuf>();


    auto read_loop = [this, socket, buf](auto&& self) -> void {
        asio::async_read_until(*socket, *buf, '\n', 
            [this, socket, buf, self](const asio::error_code& ec, std::size_t bytes_transferred) {
                if (!ec) {
                    // if (ec != asio::error::eof) {
                    //     return; 
                    // }
                    std::istream is(buf.get());
                    std::string command;
                    std::getline(is, command);
                    std::string response_body;

                    if (command == "get_warnings") {
                        auto warnings = LogUtils::get_warning_cache_snapshot();
                        nlohmann::json j;
                        j["warnings"] = warnings;
                        response_body = j.dump();
                    } else if (command == "clear_warnings") {
                        LogUtils::clear_warning_cache();
                        nlohmann::json j;
                        j["status"] = "ok";
                        response_body = j.dump();
                    } else if (command.rfind("remove_warning ", 0) == 0) {
                        std::string index_str = command.substr(std::string("remove_warning ").size());
                        try {
                            std::size_t index = std::stoul(index_str);
                            bool success = LogUtils::remove_warning_at_index(index);
                            nlohmann::json j;
                            if (success) {
                                j["status"] = "removed";
                                j["index"] = index;
                            } else {
                                j["error"] = "invalid index";
                            }
                            response_body = j.dump();
                        } catch (...) {
                            response_body = "{\"error\": \"invalid index format\"}";
                        }
                    } else {
                        response_body = "{\"error\": \"unknown command\"}";
                    }
                    response_body += "\n";
                    asio::async_write(*socket, asio::buffer(response_body),
                        [socket, self](const asio::error_code& ec, std::size_t /*length*/) {
                            if (!ec) {
                                self(self);
                            }
                        });
                }
            });
    };
    read_loop(read_loop);
}

} // namespace epollbook
