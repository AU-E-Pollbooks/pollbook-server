#include <iostream>
#include <map>
#include <vector>
#include <chrono>
#include <mutex>

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

private:
    FaultTracker() = default;
    mutable std::mutex mutex;
    ClientMap clientMap;
};
}
#endif // !FAULTY_CLIENT
