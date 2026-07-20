#include "core/config.h"
#include "utils/string_utils.h"
#include "utils/logger.h"
#include <fstream>
#include <stdexcept>

namespace core {

Config* Config::instance = nullptr;

Config::Config() : loaded(false) {
}

Config& Config::get_instance() {
    if (instance == nullptr) {
        instance = new Config();
    }
    return *instance;
}

void Config::load(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open config file: " + filename);
    }

    sections.clear();
    std::string current_section;
    std::string line;
    int line_number = 0;

    while (std::getline(file, line)) {
        line_number++;
        parse_line(line, current_section);
    }

    file.close();
    loaded = true;

    utils::Logger::get_instance().info("Configuration loaded from: " + filename);
}

void Config::parse_line(const std::string& line, std::string& /* current_section */) {
    // Trim whitespace
    std::string trimmed = utils::StringUtils::trim(line);

    // Skip empty lines and comments
    if (trimmed.empty() || trimmed[0] == '#') {
        return;
    }

    // Parse KEY=VALUE pairs (.env format)
    size_t equals_pos = trimmed.find('=');
    if (equals_pos != std::string::npos) {
        std::string key = trimmed.substr(0, equals_pos);
        std::string value = trimmed.substr(equals_pos + 1);

        key = utils::StringUtils::trim(key);
        value = utils::StringUtils::trim(value);

        // Remove quotes if present
        if (value.length() >= 2 && value.front() == '"' && value.back() == '"') {
            value = value.substr(1, value.length() - 2);
        }

        // Store in "env" section for compatibility
        sections["env"][key] = value;
    }
}

std::string Config::get(const std::string& section, const std::string& key,
                       const std::string& default_value) {
    if (!has_key(section, key)) {
        return default_value;
    }
    return sections[section][key];
}

int Config::get_int(const std::string& section, const std::string& key,
                   int default_value) {
    if (!has_key(section, key)) {
        return default_value;
    }

    try {
        return std::stoi(sections[section][key]);
    } catch (const std::exception&) {
        return default_value;
    }
}

bool Config::get_bool(const std::string& section, const std::string& key,
                     bool default_value) {
    if (!has_key(section, key)) {
        return default_value;
    }

    std::string value = utils::StringUtils::to_lower(sections[section][key]);

    if (value == "true" || value == "1" || value == "yes" || value == "on") {
        return true;
    }

    if (value == "false" || value == "0" || value == "no" || value == "off") {
        return false;
    }

    return default_value;
}

bool Config::has_key(const std::string& section, const std::string& key) {
    if (!has_section(section)) {
        return false;
    }
    return sections[section].find(key) != sections[section].end();
}

bool Config::has_section(const std::string& section) {
    return sections.find(section) != sections.end();
}

} // namespace core
