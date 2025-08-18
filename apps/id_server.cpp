#include <epollbook/config/config.hpp>
#include <epollbook/log_utils.hpp>
#include <epollbook/voter_id_service.hpp>

#include <cstdlib>
#include <iostream>

int main(int argc, char** argv) {
    std::string config_file;
    if(argc > 1) {
        config_file = argv[1];
    } else {
        config_file = "id_server_config.ini";
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
    epollbook::LogUtils::create_default_logger("id_server_log", log_level, true);
    // Create a service object
    epollbook::VoterIDService service;
    // Start it running
    service.run();
}
