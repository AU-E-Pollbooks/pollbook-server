#pragma once

#include "inifile-cpp/inicpp.h"

#include <atomic>
#include <cstdint>
#include <memory>

namespace epollbook {

/**
 * A singleton class that loads configuration options from a file and provides
 * access to them throughout the program.
 */
class Config {
private:
    /** The singleton instance */
    static std::unique_ptr<Config> instance;
    /** An atomic flag used to make initialize() thread-safe */
    static std::atomic<int> singleton_initialized_flag;
    // The three possible states of singleton_initialized_flag
    static const int STATE_UNINITIALIZED = 0;
    static const int STATE_INITIALIZING = 1;
    static const int STATE_INITIALIZED = 2;
    /** The IniFile object containing the properties parsed from a file */
    ini::IniFile parsed_config_file;
    /** Private constructor called by the initialize() method */
    Config(const std::string& config_file_path);

public:
    /**
     * Initializes the configuration object by loading an INI file from the
     * specified path and parsing it. This must be called before constructing
     * any client or server objects. This method is thread-safe.
     *
     * @param config_file_path A path to an INI file to load configuration
     * options from.
     */
    static void initialize(const std::string& config_file_path);
    /**
     * Gets a reference to the singleton configuration object. If initialize()
     * has not yet been called, this will first initialize the object with the
     * default configuration file.
     */
    static Config& getInstance();

    /**
     * Tests if the configuration object has a key with the specified
     * name in the specified section. Call this before calling a getXXX()
     * method to ensure it will succeed.
     *
     * @param section The name of the configuration file section in which
     * the key should be found
     * @param key The name of the key
     * @return true If the key exists in that section, false if it does not
     */
    bool hasKey(const std::string& section, const std::string& key);

    /**
     * Retrieves a configuration property of a specified type. This is just
     * a wrapper around the accessor methods of the inifile-cpp library.
     *
     * @tparam T The datatype of the property. This should be a built-in numeric
     * type, or std::string, otherwise conversion to this type may fail.
     * @param section The section in which the property is found
     * @param key The name of the property
     * @return The property's value, as loaded from the config file
     */
    template <typename T>
    T get(const std::string& section, const std::string& key) {
        return parsed_config_file[section][key].as<T>();
    }
    /**
     * The name of the configuration file that will be loaded by default
     * if get() is called without first calling initialize().
     */
    static const std::string DEFAULT_CONFIG_FILE;

    // Convenience methods to get a property of a particular type from the singleton instance
    static std::string getString(const std::string& section, const std::string& key);
    static std::uint16_t getUInt16(const std::string& section, const std::string& key);
    static std::uint32_t getUInt32(const std::string& section, const std::string& key);
    static std::uint64_t getUInt64(const std::string& section, const std::string& key);
    static std::int16_t getInt16(const std::string& section, const std::string& key);
    static std::int32_t getInt32(const std::string& section, const std::string& key);
    static std::int64_t getInt64(const std::string& section, const std::string& key);
    static float getFloat(const std::string& section, const std::string& key);
    static double getDouble(const std::string& section, const std::string& key);
    static bool getBool(const std::string& section, const std::string& key);
    static char getChar(const std::string& section, const std::string& key);

    // String constants for the expected configuration sections and keys.
    // Unfortunately the string values themselves cannot be defined here, even though that would be more readable.
    static const std::string SECTION_BASIC;
    /** The running client's ID number, which should be unique within this system. Not needed by servers. */
    static const std::string CLIENT_ID;
    /** The hostname (or IP) to connect to for the voter ID service */
    static const std::string ID_SERVICE_HOST;
    /** The port on which to connect to the voter ID service */
    static const std::string ID_SERVICE_PORT;
    /** The hostname (or IP) to connect to for the check-in service */
    static const std::string CHECKIN_SERVICE_HOST;
    /** The port on which to connect to the check-in service */
    static const std::string CHECKIN_SERVICE_PORT;
    /**
     * The path to a CSV file containing the list of registered voters that the
     * check-in service should use to initialize its state. This option is only
     * needed by the check-in service.
     */
    static const std::string VOTER_LIST_FILE;
    /** The logging level to use for the default logger (trace, debug, info, warning, critical, error) */
    static const std::string LOG_LEVEL;

    static const std::string SECTION_SECURITY;
    /** The path to a file containing the private key for the running program (client or sever) */
    static const std::string LOCAL_PRIVATE_KEY;
    /** The path to a file containing the public key for the voter ID service */
    static const std::string ID_SERVICE_PUBLIC_KEY;
    /** The path to a file containing the public key for the check-in service */
    static const std::string CHECKIN_SERVICE_PUBLIC_KEY;
    /**
     * A folder containing public keys for clients in the system, named by their client IDs.
     * This option is not needed by clients.
     */
    static const std::string CLIENT_KEYS_FOLDER;
    /**
     * The prefix for the names of files containing client public keys; the
     * client's ID and the extension ".pem" will be appended to this prefix
     * when searching for a client's key.
     */
    static const std::string CLIENT_KEY_FILE_PREFIX;
    /**
     * The time, in milliseconds, within which a client's request is considered
     * fresh enough. Requests older than this will be considered stale.
     */
    static const std::string REQUEST_FRESHNESS_INTERVAL;
    /**
     * The path to the file containing the certificate for the check-in service
    */
    static const std::string CHECKIN_SERVICE_CERT;
    /**
     * The path to the file containing the certificate for the voter id service
    */
    static const std::string ID_SERVICE_CERT;
    /**
     * The path to the file containing the certificate for the running program (client or server)
    */
    static const std::string LOCAL_CERT;
    /**
     * The path to the file containing the certificate for the certificate authority
    */
    static const std::string CA_CERT;
};

}  // namespace epollbook
