#include <iostream>
#include <map>
#include <vector>
#include <chrono>
#include <mutex>
#include <nlohmann/json.hpp>
#include <epollbook/config/config.hpp>
#include <epollbook/log_utils.hpp>

#ifndef FAULTY_CLIENT_H
#define FAULTY_CLIENT_H

namespace epollbook {

struct FaultyClientRecord {
    std::chrono::system_clock::time_point lastReportTime;
    std::vector<std::string> faultDescriptions;

    // Add JSON serialization
    nlohmann::json to_json() const {
        nlohmann::json j;
        j["lastReportTime"] = std::chrono::system_clock::to_time_t(lastReportTime);
        j["faultDescriptions"] = faultDescriptions;
        return j;
    }

    static FaultyClientRecord from_json(const nlohmann::json& j) {
        FaultyClientRecord record;
        record.lastReportTime = std::chrono::system_clock::from_time_t(j["lastReportTime"]);
        record.faultDescriptions = j["faultDescriptions"].get<std::vector<std::string>>();
        return record;
    }
};
using ClientMap = std::unordered_map<uint32_t, FaultyClientRecord>;

class FaultTracker {
public:
    static FaultTracker& getInstance() {
        static FaultTracker instance;
        return instance;
    }

    void reportFault(uint32_t client_id, const std::string& faultDesc) {
        std::lock_guard<std::mutex> lock(mutex);
        auto& record = clientMap[client_id];
        record.lastReportTime = std::chrono::system_clock::now();
        record.faultDescriptions.push_back(faultDesc);

        // logger->warn("Client {} fault reported: {}", client_id, faultDesc);
    }

    ClientMap getSnapshot() const {
        std::lock_guard<std::mutex> lock(mutex);
        return clientMap;
    }

    void clearClient(uint32_t client_id) {
        std::lock_guard<std::mutex> lock(mutex);
        clientMap.erase(client_id);
        // logger->info("Cleared fault history for client {}", client_id);
    }

    void clearOldRecords(std::chrono::hours threshold) {
        std::lock_guard<std::mutex> lock(mutex);
        auto now = std::chrono::system_clock::now();
        for (auto it = clientMap.begin(); it != clientMap.end();) {
            if (now - it->second.lastReportTime > threshold) {
                // logger->info("Removing old fault records for client {}", it->first);
                it = clientMap.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Start the network listener for REPL commands
    void startNetworkListener(uint16_t port = 5556) {
        if (network_thread) {
            return; // Already running
        }

        network_thread = std::make_unique<std::thread>([this, port]() {
            try {
                asio::io_context io_context;
                asio::ip::tcp::acceptor acceptor(io_context,
                    asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port));

                while (running) {
                    asio::ip::tcp::socket socket(io_context);
                    acceptor.accept(socket);

                    // Read the command
                    asio::streambuf buf;
                    asio::read_until(socket, buf, "\n");
                    std::string data{std::istreambuf_iterator<char>(&buf),
                                   std::istreambuf_iterator<char>()};

                    // Process command and send response
                    auto response = handleCommand(data);
                    asio::write(socket, asio::buffer(response + "\n"));
                }
            } catch (const std::exception& e) {
                if (auto logger = spdlog::get("server_log")) {
                    logger->error("Network error: {}", e.what());
                }
            }
        });
    }

    void stopNetworkListener() {
        running = false;
        if (network_thread && network_thread->joinable()) {
            network_thread->join();
        }
    }

    void initializeConfig() {
        try {
            if (Config::getInstance().hasKey("FaultTracking", "cleanup_hours")) {
                cleanup_threshold = std::chrono::hours(
                    Config::getInt32("FaultTracking", "cleanup_hours")
                );
            }
        } catch (const std::exception& e) {
            // Default to 24 hours if config read fails
            cleanup_threshold = std::chrono::hours(24);
            if (auto logger = spdlog::get("server_log")) {
                logger->info("Using default fault cleanup threshold of 24 hours");
            }
        }
    }


private:
    FaultTracker() {
        initializeConfig();
    }
    std::string handleCommand(const std::string& data) {
        try {
            auto j = nlohmann::json::parse(data);
            std::string command = j["command"];

            nlohmann::json response;
            if (command == "list") {
                response["data"] = getAllClientsJson();
            }
            else if (command == "show" && j.contains("client_id")) {
                response["data"] = getClientJson(j["client_id"]);
            }
            else if (command == "clear" && j.contains("client_id")) {
                clearClient(j["client_id"]);
                response["data"] = "Cleared client " + std::to_string(j["client_id"].get<uint32_t>());
            }
            else {
                response["error"] = "Invalid command";
            }
            return response.dump();
        }
        catch (const std::exception& e) {
            nlohmann::json error_response;
            error_response["error"] = e.what();
            return error_response.dump();
        }
    }

    nlohmann::json getAllClientsJson() const {
        std::lock_guard<std::mutex> lock(mutex);
        nlohmann::json j;
        for (const auto& [client_id, record] : clientMap) {
            j[std::to_string(client_id)] = record.to_json();
        }
        return j;
    }

    nlohmann::json getClientJson(uint32_t client_id) const {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = clientMap.find(client_id);
        if (it != clientMap.end()) {
            return it->second.to_json();
        }
        return nlohmann::json::object();
    }

    mutable std::mutex mutex;
    ClientMap clientMap;
    std::chrono::hours cleanup_threshold{24};
};
}
#endif // !FAULTY_CLIENT
