#include "epollbook/log_utils.hpp"

#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <vector>

namespace epollbook {

std::unique_ptr<LogUtils> LogUtils::instance;

void LogUtils::initialize() {
    if(!instance) {
        // Can't use make_unique because the constructor is private
        instance = std::unique_ptr<LogUtils>(new LogUtils());
    }
}

void LogUtils::create_default_logger(const std::string& logger_name,
                                     spdlog::level::level_enum log_level) {
    initialize();
    instance->make_default_logger(logger_name, log_level);
}

std::string LogUtils::get_default_logger_name() {
    initialize();
    return instance->default_logger_name;
}

void LogUtils::make_default_logger(const std::string& logger_name,
                                   spdlog::level::level_enum log_level) {
    default_logger_name = logger_name;
    std::vector<spdlog::sink_ptr> log_sinks;
    log_sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        logger_name + ".log", 1L << 20, 10));
    log_sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
    spdlog::init_thread_pool(1L << 20, 1);
    std::shared_ptr<spdlog::logger> log = std::make_shared<spdlog::async_logger>(
        logger_name,
        log_sinks.begin(),
        log_sinks.end(),
        spdlog::thread_pool(),
        spdlog::async_overflow_policy::block);
    spdlog::register_logger(log);
    log->set_pattern("[%H:%M:%S.%f] [%n] [Thread %t] [%^%l%$] %v");
    log->set_level(log_level);
}

}  // namespace epollbook