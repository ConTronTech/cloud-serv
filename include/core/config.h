#pragma once

#include <string>
#include <map>

namespace core {

class Config {
private:
    std::map<std::string, std::map<std::string, std::string>> sections;
    static Config* instance;
    bool loaded;

    Config();
    void parse_line(const std::string& line, std::string& current_section);

public:
    static Config& get_instance();

    // Prevent copying
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;

    // Load configuration from file
    void load(const std::string& filename);

    // Get string value
    std::string get(const std::string& section, const std::string& key,
                   const std::string& default_value = "");

    // Get integer value
    int get_int(const std::string& section, const std::string& key,
               int default_value = 0);

    // Get boolean value
    bool get_bool(const std::string& section, const std::string& key,
                 bool default_value = false);

    // Check if key exists
    bool has_key(const std::string& section, const std::string& key);

    // Check if section exists
    bool has_section(const std::string& section);

    // Check if config is loaded
    bool is_loaded() const { return loaded; }
};

} // namespace core
