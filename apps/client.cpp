#include <epollbook/pollbook_client.hpp>
#include <epollbook/config/config.hpp>
#include <epollbook/log_utils.hpp>

#include <iostream>
#include <string>

int main(int argc, char** argv) {
    std::string config_file;
    if(argc > 1) {
        config_file = argv[1];
    } else {
        config_file = "client_config.ini";
    }
    // Read the configuration file
    epollbook::Config::initialize(config_file);
    // Set up the logger
    epollbook::LogUtils::create_default_logger("client_log");

    epollbook::PollbookClient client;
    client.connect();
    std::cout << "Connected to checkin server and ID server" << std::endl;

    std::string message;
    std::cout << "Enter a test message to send" << std::endl;
    std::getline(std::cin, message);

    client.send_string_message(message);

}