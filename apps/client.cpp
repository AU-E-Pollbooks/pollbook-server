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
    epollbook::LogUtils::create_default_logger("client_log", spdlog::level::trace);

    epollbook::PollbookClient client;
    client.connect();
    std::cout << "Connected to checkin server and ID server" << std::endl;

    std::string first, middle, last;
    std::uint32_t id_document_num;
    std::cout << "Enter the voter's last name" << std::endl;
    std::getline(std::cin, last);
    std::cout << "Enter the voter's first name" << std::endl;
    std::getline(std::cin, first);
    std::cout << "Enter the voter's middle name" << std::endl;
    std::getline(std::cin, middle);
    std::cout << "Enter the voter's ID document number" << std::endl;
    std::cin >> id_document_num;

    // Use some dummy data to represent the "image of the voter's ID" (the ID service will accept any ID data right now)
    std::vector<std::uint8_t> voter_id_data = {0x1a, 0x1b, 0x1c, 0x1d, 0x2a, 0x2b, 0x2c, 0x2d,
                                               0xff, 0xff, 0xff, 0xff, 0x1, 0x1, 0x1, 0x1,
                                               0x1a, 0x1b, 0x1c, 0x1d, 0x2a, 0x2b, 0x2c, 0x2d};

    std::cout << "Sending a check-in request..." << std::endl;
    auto result_future = client.check_in_voter(first, middle, last, id_document_num, voter_id_data);
    std::cout << "Awaiting the result..." << std::endl;
    epollbook::CheckinResult result = result_future.get();
    if(result.success) {
        std::cout << "Check-in succeeded!" << std::endl;
    } else {
        std::cout << "Check-in failed! Reason: " << result.failure_reason << std::endl;
    }
}
