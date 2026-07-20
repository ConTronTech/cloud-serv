#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <memory>

namespace utils {

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
    FATAL = 4
};

class Logger {
private:
    std::ofstream log_file;
    std::mutex log_mutex;
    LogLevel current_level;
    bool console_output;
    bool file_output;
    size_t max_file_size;
    size_t current_file_size;
    std::string log_directory;
    std::string log_filename;
    int max_files;

    Logger();

    void rotate_logs();
    std::string format_message(LogLevel level, const std::string& msg);
    std::string level_to_string(LogLevel level);
    std::string get_timestamp();
    void write_log(LogLevel level, const std::string& message);

public:
    static Logger& get_instance();

    // Prevent copying
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    // Initialize logger (Docker-friendly - stdout/stderr only)
    void init(LogLevel level = LogLevel::INFO);

    // Logging methods
    void log(LogLevel level, const std::string& message);
    void debug(const std::string& msg);
    void info(const std::string& msg);
    void warn(const std::string& msg);
    void error(const std::string& msg);
    void fatal(const std::string& msg);

    // Structured logging for HTTP requests
    void log_request(const std::string& client_ip,
                    const std::string& method,
                    const std::string& path,
                    int status_code,
                    size_t response_size,
                    long duration_ms);

    // Set log level
    void set_level(LogLevel level);

    // Close log file
    void close();

    ~Logger();
};

} // namespace utils
