#include <iostream>
#include <map>
#include <vector>
#include <chrono>
#include <mutex>
#include <epollbook/config/config.hpp>
#include <epollbook/log_utils.hpp>

#ifndef FAULTY_CLIENT_H
#define FAULTY_CLIENT_H

namespace epollbook {

struct FaultyClientRecord {
    std::chrono::system_clock::time_point lastReportTime;
    std::vector<std::string> faultDescriptions;
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
    };
    mutable std::mutex mutex;
    ClientMap clientMap;
    std::chrono::hours cleanup_threshold{24};
};
}
#endif // !FAULTY_CLIENT
