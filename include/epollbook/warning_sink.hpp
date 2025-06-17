#include <spdlog/sinks/base_sink.h>
#include <mutex>
#include <shared_mutex>


namespace epollbook {
template<typename Mutex = std::shared_mutex> 
class WarningCacheSink : public spdlog::sinks::base_sink<Mutex> {
public:
    std::vector<std::string> get_warnings_snapshot() const {
        std::shared_lock<Mutex> lock(mutex_);
        return warnings;
    }
    void clear() {
        std::unique_lock<Mutex> lock(mutex_);
        warnings.clear();
    }
protected:
    void sink_it_(const spdlog::details::log_msg& msg) override {
        if (msg.level == spdlog::level::warn) {
            spdlog::memory_buf_t formatted;
            this->formatter_-> format(msg, formatted);
            std::lock_guard<Mutex> lock(this->mutex_);
            warnings.emplace_back(fmt::to_string(formatted));
        }
    }


    void flush_() override {
        // no opping this sink
    }
private:
    std::vector<std::string> warnings;
    mutable Mutex mutex_;
};

} // namespace epollbook



#include <spdlog/sinks/base_sink-inl.h>
