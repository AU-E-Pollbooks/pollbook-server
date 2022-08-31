#include <epollbook/voter_id_service.hpp>
#include <epollbook/config/config.hpp>
#include <epollbook/log_utils.hpp>

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
    epollbook::LogUtils::create_default_logger("id_server_log");
    // Create a service object
    epollbook::VoterIDService service;
    // Start it running
    service.run();
}