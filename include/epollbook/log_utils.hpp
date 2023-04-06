#pragma once

#include <spdlog/fmt/bin_to_hex.h>
#include <spdlog/fmt/ostr.h>
#include <spdlog/spdlog.h>

#include <memory>
#include <string>

namespace epollbook {

/**
 * A simple singleton class that contains some utility functions for
 * setting up the logging system.
 */
class LogUtils {
private:
    /** The single instance of LogUtils */
    static std::unique_ptr<LogUtils> instance;
    /** The name of the default logger that was registered with spdlog */
    std::string default_logger_name;
    void make_default_logger(const std::string& logger_name,
                             spdlog::level::level_enum log_level = spdlog::level::debug);
    /** Constructs the single instance if it does not already exist */
    static void initialize();
    /** Private constructor; only one instance should be constructed */
    LogUtils() = default;

public:
    /**
     * Creates a logger object that will be used by all epollbook library
     * classes as the default logger, and registers it with spdlog's
     * registry.
     */
    static void create_default_logger(const std::string& logger_name,
                                      spdlog::level::level_enum log_level = spdlog::level::debug);
    /**
     * Gets the name of the default, global logger for the epollbook
     * library that was created earlier by create_default_logger. Can
     * be used to retrieve a pointer to the logger from spdlog's registry.
     */
    static std::string get_default_logger_name();
};

}  // namespace epollbook
