#include <epollbook/pollbook_client.hpp>

#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if(argc < 3) {
        std::cout << "Insufficient arguments." << std::endl;
        std::cout << "Usage: " << argv[0] << " server_hostname server_port " << std::endl;
        return -1;
    }
    std::string hostname(argv[1]);
    std::string port(argv[2]);

    epollbook::PollbookClient client;
    client.connect(hostname, port);
    std::cout << "Connected to " << hostname << " on port " << port << std::endl;

    std::string message;
    std::cout << "Enter a test message to send" << std::endl;
    std::getline(std::cin, message);

    client.send_string_message(message);

}