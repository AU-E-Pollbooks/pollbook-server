#include <epollbook/checkin_service.hpp>
#include <epollbook/config/config.hpp>
#include <epollbook/log_utils.hpp>

#include <cstdlib>
#include <iostream>

int main(int argc, char** argv) {
    std::string config_file;
    if(argc > 1) {
        config_file = argv[1];
    } else {
        config_file = "server_config.ini";
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
    epollbook::LogUtils::create_default_logger("server_log", log_level, true);
    // Create a service object

    bool running = true;
    std::unique_ptr<epollbook::CheckinService> service;
    std::unique_ptr<std::thread> server_thread;

    while (running) {
        std::cout << "epollbook> ";
        std::string command;
        std::getline(std::cin, command);

        if (command == "help") {
            std::cout << "Available commands:\n"
                     << "  list        - List all clients with faults\n"
                     << "  show <id>   - Show faults for specific client\n"
                     << "  clear <id>  - Clear fault history for client\n"
                     << "  runserver   - Start the server\n"
                     << "  quit        - Exit program\n";
        } else if (command == "runserver") {
            if (!server_thread) {
                service = std::make_unique<epollbook::CheckinService>();
                server_thread = std::make_unique<std::thread>([&service]() {
                    service->run();
                });
                std::cout << "Server started\n";
            } else {
                std::cout << "Server is already running\n";
            }
        } else if (command == "list") {
            auto snapshot = epollbook::FaultTracker::getInstance().getSnapshot();
            for (const auto& [id, record] : snapshot) {
                std::cout << "Client " << id << ": "
                         << record.faultDescriptions.size() << " faults\n";
            }
        } else if (command == "test") {
            epollbook::LogUtils::create_default_logger("test_logger", log_level, true);
            spdlog::get("test_logger")->info("This is an info message");
            spdlog::get("test_logger")->warn("Warning: something weird happened");
            spdlog::get("test_logger")->warn("Another warning message");
            spdlog::get("test_logger")->error("An error occurred");
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            auto warnings = epollbook::LogUtils::get_warning_cache_snapshot();
            nlohmann::json j;
            j["warnings"] = warnings;
            std::cout << j.dump(4) << std::endl;


            // Clear cache and verify it's empty
            epollbook::LogUtils::clear_warning_cache();
            auto warnings_after_clear = epollbook::LogUtils::get_warning_cache_snapshot();
            std::cout << "Warnings after clear: " << warnings_after_clear.size() << " entries\n";
        } else if (command.substr(0, 4) == "show") {
            try {
                uint32_t client_id = std::stoul(command.substr(5));
                auto snapshot = epollbook::FaultTracker::getInstance().getSnapshot();
                auto it = snapshot.find(client_id);
                if (it != snapshot.end()) {
                    const auto& record = it->second;
                    std::cout << "Client " << client_id << " faults:\n";
                    for (const auto& desc : record.faultDescriptions) {
                        std::cout << "- " << desc << "\n";
                    }
                } else {
                    std::cout << "No faults found for client " << client_id << "\n";
                }
            } catch (...) {
                std::cout << "Invalid client ID\n";
            }
        } else if (command.substr(0, 5) == "clear") {
            try {
                uint32_t client_id = std::stoul(command.substr(6));
                epollbook::FaultTracker::getInstance().clearClient(client_id);
                std::cout << "Cleared fault history for client " << client_id << "\n";
            } catch (...) {
                std::cout << "Invalid client ID\n";
            }
        } else if (command == "quit") {
            if (server_thread) {
                service.reset();  // You'll need to implement this
                server_thread->join();
            }
            running = false;
        } else {
            std::cout << "Unknown command. Type 'help' for available commands.\n";
        }
    }

}
