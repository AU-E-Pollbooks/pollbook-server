#include <iostream>
#include <map>
#include <vector>
#include <chrono>

namespace epollbook {

struct FaultyClientRecord {
    std::chrono::system_clock::time_point lastReportTime;
    std::vector<std::string> faultDescriptions;
};
using ClientMap = std::unordered_map<uint32_t, FaultyClientRecord>;

class FaultyClientTracker {
public:
    static void reportFault(ClientMap& clientMap, uint32_t client_id, const std::string& faultDescriptions) {
        auto& record = clientMap[client_id];
        record.lastReportTime - std::chrono::system_clock::now();
        record.faultDescriptions.push_back(faultDescriptions);
    }

    static void printClientReport(ClientMap& clientMap, uint32_t client_id) {
        auto it = clientMap.find(client_id);
        if (it != clientMap.end()) {
            const auto& record = it->second;
            std::cout << "Client ID: " << client_id << std::endl;
            std::cout << "Fault Count: " << record.faultDescriptions.size() << std::endl;
            std::cout << "Last Report Time: " << std::chrono::system_clock::to_time_t(record.lastReportTime) << std::endl;
            std::cout << "Fault Descriptions:" << std::endl;
            for (const auto& desc : record.faultDescriptions) {
                std::cout << "- " << desc << std::endl;
            }
        } else {
            std::cout << "No record found for client ID: " << client_id << std::endl;
        }
    }

};
}
