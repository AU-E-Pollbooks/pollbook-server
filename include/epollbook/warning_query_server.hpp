#pragma once


#include "epollbook/log_utils.hpp"

#include <nlohmann/json.hpp>
#include <iostream>
#include <memory>
#include <asio/read_until.hpp>
#include <asio/streambuf.hpp>
#include <asio/write.hpp>


namespace epollbook {

class WarningQueryServer {

public:
    WarningQueryServer(asio::io_context&, unsigned short port);
    void start_accept();

private:
    void handle_accept(std::shared_ptr<asio::ip::tcp::socket> socket, 
                       const asio::error_code& err);
    void handle_session(std::shared_ptr<asio::ip::tcp::socket> socket);
    asio::ip::tcp::acceptor acceptor;
};

}
