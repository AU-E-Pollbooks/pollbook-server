#include <epollbook/config/config.hpp>
#include <epollbook/log_utils.hpp>
#include <epollbook/pollbook_client.hpp>

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
    spdlog::level::level_enum log_level;
    if(epollbook::Config::getInstance().hasKey(epollbook::Config::SECTION_BASIC, epollbook::Config::LOG_LEVEL)) {
        log_level = spdlog::level::from_str(epollbook::Config::getString(epollbook::Config::SECTION_BASIC, epollbook::Config::LOG_LEVEL));
    } else {
        log_level = spdlog::level::debug;
    }
    epollbook::LogUtils::create_default_logger("client_log", log_level);

    epollbook::PollbookClient client;
    // connect to just the id server instead of both
    /* client.connect_checkin_server(); */
    client.connect_checkin_server(
            epollbook::Config::getString(
                    epollbook::Config::SECTION_BASIC, 
                    epollbook::Config::CHECKIN_SERVICE_HOST
                ),
            epollbook::Config::getString(
                    epollbook::Config::SECTION_BASIC, 
                    epollbook::Config::CHECKIN_SERVICE_PORT
                )
            );
    std::cout << "Connected to Check In server" << std::endl;

    std::string ticket;
    std::cout << "Enter ticket for client" <<std::endl;
    std::cin >> ticket;

    //Send ticket to checkin server to fully check in voter
    client.send_string_message(ticket);
    std::string response = client.receive_string_message();
    std::cout << "Server response: " << response << std::endl;
}
