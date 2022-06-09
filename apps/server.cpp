#include <epollbook/checkin_service.hpp>
#include <epollbook/log_utils.hpp>

#include <iostream>
#include <cstdlib>

int main(int argc, char** argv) {
    if(argc < 2) {
        std::cout << "Error: Missing server port argument" << std::endl;
        return -1;
    }
    uint16_t port = std::atoi(argv[1]);
    //Set up the logger
    epollbook::LogUtils::create_default_logger("server_log");
    //Create a service object
    epollbook::CheckinService service(port);
    //Start it running
    service.run();
}