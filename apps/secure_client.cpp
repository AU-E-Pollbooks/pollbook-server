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
    std::string first, middle, last;
    std::uint32_t voter_unique_id;
    std::uint32_t pin;
    std::cout << "Enter the voter's last name" << std::endl;
    std::getline(std::cin, last);
    std::cout << "Enter the voter's first name" << std::endl;
    std::getline(std::cin, first);
    std::cout << "Enter the voter's middle name" << std::endl;
    std::getline(std::cin, middle);
    std::cout << "Enter the voter's unique ID number" << std::endl;
    std::cin >> voter_unique_id;
    std::string ticket;
    std::cout << "Enter ticket for client" << std::endl;
    std::cin >> ticket;
    std::cout << "Enter your pin" << std::endl;
    std::cin >> pin;

    // Use some dummy data to represent the "image of the voter's ID" (the ID service will accept any ID data right now)
    std::vector<std::uint8_t> voter_id_data = {0x1a, 0x1b, 0x1c, 0x1d, 0x2a, 0x2b, 0x2c, 0x2d,
                                               0xff, 0xff, 0xff, 0xff, 0x1, 0x1, 0x1, 0x1,
                                               0x1a, 0x1b, 0x1c, 0x1d, 0x2a, 0x2b, 0x2c, 0x2d};

    std::cout << "Sending a check-in request..." << std::endl;
    auto result_future = client.verify_ticket(first, middle, last, voter_unique_id, ticket, pin);
    // std::cout << "Awaiting the result..." << std::endl;
    // std::cout << "Connected to Check In server" << std::endl;
    epollbook::CheckinResult result = result_future.get();
    if(result.success) {
        std::cout << "Ticket verification succeeded!" << std::endl;
    } else {
        std::cout << "Ticket verification failed! Reason: " << result.failure_reason << std::endl;
    }


    ////Send ticket to checkin server to fully check in voter
    //client.send_string_message(ticket);
    //std::string response = client.receive_string_message();
    //std::cout << "Response read\n";
    //std::cout << "Server response: " << response << std::endl;
}
