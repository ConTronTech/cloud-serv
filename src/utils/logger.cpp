#include "utils/logger.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <ctime>

namespace utils {

Logger::Logger()
    : current_level(LogLevel::INFO)
    , console_output(true)
    , file_output(false)
    , max_file_size(0)
    , current_file_size(0)
    , log_directory("")
    , log_filename("")
    , max_files(0) {
}

Logger::~Logger() {
    close();
}

Logger& Logger::get_instance() {
    static Logger instance;
    return instance;
}

void Logger::init(LogLevel level) {
    std::lock_guard<std::mutex> lock(log_mutex);
    current_level = level;
    console_output = true;
    file_output = false;  // Docker handles logging via stdout/stderr
}

void Logger::set_level(LogLevel level) {
    std::lock_guard<std::mutex> lock(log_mutex);
    current_level = level;
}

void Logger::close() {
    std::lock_guard<std::mutex> lock(log_mutex);
    if (log_file.is_open()) {
        log_file.close();
    }
}

std::string Logger::get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm tm_now;
    localtime_r(&time_t_now, &tm_now);

    std::ostringstream oss;
    oss << std::put_time(&tm_now, "%Y-%m-%d %H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

std::string Logger::level_to_string(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

std::string Logger::format_message(LogLevel level, const std::string& msg) {
    std::ostringstream oss;
    oss << "[" << get_timestamp() << "] "
        << "[" << level_to_string(level) << "] "
        << msg;
    return oss.str();
}

void Logger::rotate_logs() {
    if (!log_file.is_open() || current_file_size < max_file_size) {
        return;
    }

    log_file.close();

    namespace fs = std::filesystem;

    // Rotate existing log files
    for (int i = max_files - 1; i > 0; --i) {
        std::string old_name = log_directory + "/" + log_filename + "." + std::to_string(i);
        std::string new_name = log_directory + "/" + log_filename + "." + std::to_string(i + 1);

        if (fs::exists(old_name)) {
            if (i == max_files - 1) {
                fs::remove(old_name);  // Delete oldest
            } else {
                fs::rename(old_name, new_name);
            }
        }
    }

    // Rename current log file
    std::string current_path = log_directory + "/" + log_filename;
    std::string rotated_path = current_path + ".1";
    if (fs::exists(current_path)) {
        fs::rename(current_path, rotated_path);
    }

    // Open new log file
    log_file.open(current_path, std::ios::app);
    current_file_size = 0;
}

void Logger::write_log(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex);

    if (level < current_level) {
        return;  // Don't log if below current level
    }

    std::string formatted = format_message(level, message);

    // Docker-friendly: all logs to stdout (Docker captures and manages them)
    if (level >= LogLevel::ERROR) {
        std::cerr << formatted << std::endl;
    } else {
        std::cout << formatted << std::endl;
    }
}

void Logger::log(LogLevel level, const std::string& message) {
    write_log(level, message);
}

void Logger::debug(const std::string& msg) {
    write_log(LogLevel::DEBUG, msg);
}

void Logger::info(const std::string& msg) {
    write_log(LogLevel::INFO, msg);
}

void Logger::warn(const std::string& msg) {
    write_log(LogLevel::WARN, msg);
}

void Logger::error(const std::string& msg) {
    write_log(LogLevel::ERROR, msg);
}

void Logger::fatal(const std::string& msg) {
    write_log(LogLevel::FATAL, msg);
}

void Logger::log_request(const std::string& client_ip,
                        const std::string& method,
                        const std::string& path,
                        int status_code,
                        size_t response_size,
                        long duration_ms) {
    std::ostringstream oss;
    oss << "[REQUEST] " << client_ip << " " << method << " " << path
        << " " << status_code << " " << response_size << " bytes "
        << duration_ms << "ms";
    write_log(LogLevel::INFO, oss.str());
}

} // namespace utils
