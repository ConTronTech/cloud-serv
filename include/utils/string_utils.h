#pragma once

#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

namespace utils {

class StringUtils {
public:
    // Trim whitespace from both ends of string
    static std::string trim(const std::string& str);

    // Trim whitespace from left side
    static std::string ltrim(const std::string& str);

    // Trim whitespace from right side
    static std::string rtrim(const std::string& str);

    // Split string by delimiter
    static std::vector<std::string> split(const std::string& str, char delimiter);

    // Convert string to lowercase
    static std::string to_lower(const std::string& str);

    // Convert string to uppercase
    static std::string to_upper(const std::string& str);

    // Check if string starts with prefix
    static bool starts_with(const std::string& str, const std::string& prefix);

    // Check if string ends with suffix
    static bool ends_with(const std::string& str, const std::string& suffix);

    // Remove all occurrences of characters in string
    static std::string remove_chars(const std::string& str, const std::string& chars);
};

} // namespace utils
