#include "epollbook/config/config.hpp"
#include "epollbook/config/inifile-cpp/inicpp.h"

#include <string>

namespace epollbook {

const std::string Config::DEFAULT_CONFIG_FILE = "config.ini";

const std::string Config::SECTION_BASIC = "Basic";
const std::string Config::CLIENT_ID = "client_id";
const std::string Config::ID_SERVICE_HOST = "id_service_host";
const std::string Config::ID_SERVICE_PORT = "id_service_port";
const std::string Config::CHECKIN_SERVICE_HOST = "checkin_service_host";
const std::string Config::CHECKIN_SERVICE_PORT = "checkin_service_port";
const std::string Config::VOTER_LIST_FILE = "voter_list_file";
const std::string Config::TRUSTED_CLIENTS_FILE = "trusted_clients_file";
const std::string Config::LOG_LEVEL = "log_level";
const std::string Config::SECTION_SECURITY = "Security";
const std::string Config::LOCAL_PRIVATE_KEY = "private_key";
const std::string Config::ID_SERVICE_PUBLIC_KEY = "id_service_public_key";
const std::string Config::CHECKIN_SERVICE_PUBLIC_KEY = "checkin_service_public_key";
const std::string Config::CLIENT_KEYS_FOLDER = "client_keys_folder";
const std::string Config::CLIENT_KEY_FILE_PREFIX = "client_key_file_prefix";
const std::string Config::REQUEST_FRESHNESS_INTERVAL = "request_freshness_interval";
// const std::string Config::FAULTY_CLEANUP_TIME = "faulty_cleanup_time"; 

const std::string Config::CHECKIN_SERVICE_CERT = "checkin_service_cert";
const std::string Config::ID_SERVICE_CERT = "id_service_cert";
const std::string Config::LOCAL_CERT = "local_cert";
const std::string Config::CA_CERT = "ca_cert";
const std::string Config::TIMEOUT_INTERVAL = "timeout_interval";

std::atomic<int> Config::singleton_initialized_flag = 0;

// This static variable must be re-declared here even though it is not initialized here
std::unique_ptr<Config> Config::instance;

Config::Config(const std::string& config_file_path) {
    // The IniFile object should be default-constructed, then initialized
    parsed_config_file.setMultiLineValues(true);
    parsed_config_file.load(config_file_path);
    // Sanity test config file
    if(parsed_config_file.find(SECTION_BASIC) == parsed_config_file.end()) {
        throw std::logic_error("Configuration file error: Required section [" + SECTION_BASIC + "] not found");
    }
    if(parsed_config_file.find(SECTION_SECURITY) == parsed_config_file.end()) {
        throw std::logic_error("Configuration file error: Required section [" + SECTION_SECURITY + "] not found");
    }
    if(!hasKey(SECTION_SECURITY, LOCAL_PRIVATE_KEY)) {
        throw std::logic_error("Configuration file error: Required key " + LOCAL_PRIVATE_KEY + " not found");
    }
}

Config& Config::getInstance() {
    while(Config::singleton_initialized_flag.load(std::memory_order_acquire) != STATE_INITIALIZED) {
        Config::initialize(DEFAULT_CONFIG_FILE);
    }
    return *instance;
}

void Config::initialize(const std::string& config_file_path) {
    int expected_uninitialized = STATE_UNINITIALIZED;
    if(singleton_initialized_flag.compare_exchange_strong(
           expected_uninitialized, STATE_INITIALIZING, std::memory_order_acq_rel)) {
        // make_unique doesn't work if the constructor is private
        instance = std::unique_ptr<Config>(new Config(config_file_path));
        singleton_initialized_flag.store(STATE_INITIALIZED, std::memory_order_acq_rel);
    }
    // make sure concurrent callers only return when initialization has finished
    while(singleton_initialized_flag.load(std::memory_order_acquire) != STATE_INITIALIZED) {
    }
}

bool Config::hasKey(const std::string& section, const std::string& key) {
    return parsed_config_file[section].find(key) != parsed_config_file[section].end();
}

std::int16_t Config::getInt16(const std::string& section, const std::string& key) {
    return getInstance().get<std::int16_t>(section, key);
}

std::int32_t Config::getInt32(const std::string& section, const std::string& key) {
    return getInstance().get<std::int32_t>(section, key);
}

std::int64_t Config::getInt64(const std::string& section, const std::string& key) {
    return getInstance().get<std::int64_t>(section, key);
}

std::uint16_t Config::getUInt16(const std::string& section, const std::string& key) {
    return getInstance().get<std::uint16_t>(section, key);
}

std::uint32_t Config::getUInt32(const std::string& section, const std::string& key) {
    return getInstance().get<std::uint32_t>(section, key);
}

std::uint64_t Config::getUInt64(const std::string& section, const std::string& key) {
    return getInstance().get<std::uint64_t>(section, key);
}

std::string Config::getString(const std::string& section, const std::string& key) {
    return getInstance().get<std::string>(section, key);
}

bool Config::getBool(const std::string& section, const std::string& key) {
    return getInstance().get<bool>(section, key);
}

double Config::getDouble(const std::string& section, const std::string& key) {
    return getInstance().get<double>(section, key);
}

float Config::getFloat(const std::string& section, const std::string& key) {
    return getInstance().get<float>(section, key);
}

char Config::getChar(const std::string& section, const std::string& key) {
    return getInstance().get<char>(section, key);
}

}  // namespace epollbook
