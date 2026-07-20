#include "security/sanitizer.h"
#include "utils/string_utils.h"
#include "utils/logger.h"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace security {

std::vector<std::string> Sanitizer::allowedExtensions_ = Sanitizer::defaultExtensions();

std::vector<std::string> Sanitizer::defaultExtensions() {
    return {".md", ".json", ".txt", ".yaml", ".yml"};
}

void Sanitizer::loadAllowedExtensions(const std::string& extensionList) {
    allowedExtensions_.clear();
    auto parts = utils::StringUtils::split(extensionList, ',');
    for (auto& ext : parts) {
        ext = utils::StringUtils::trim(ext);
        if (!ext.empty()) {
            // Ensure extension starts with dot
            if (ext[0] != '.') ext = "." + ext;
            allowedExtensions_.push_back(utils::StringUtils::to_lower(ext));
        }
    }
    if (allowedExtensions_.empty()) {
        allowedExtensions_ = defaultExtensions();
    }
    utils::Logger::get_instance().info("Loaded " + std::to_string(allowedExtensions_.size()) + " allowed file extensions");
}

bool Sanitizer::isValidSlug(const std::string& slug) {
    if (slug.empty() || slug.length() > 64) {
        return false;
    }
    for (char c : slug) {
        if (!std::islower(static_cast<unsigned char>(c)) &&
            !std::isdigit(static_cast<unsigned char>(c)) &&
            c != '_' && c != '-') {
            return false;
        }
    }
    // Must not start or end with - or _
    if (slug.front() == '-' || slug.front() == '_' ||
        slug.back() == '-' || slug.back() == '_') {
        return false;
    }
    return true;
}

std::string Sanitizer::sanitizeSlug(const std::string& input) {
    std::string result;
    std::string lower = utils::StringUtils::to_lower(input);
    for (char c : lower) {
        if (std::islower(static_cast<unsigned char>(c)) ||
            std::isdigit(static_cast<unsigned char>(c)) ||
            c == '_' || c == '-') {
            result += c;
        }
    }
    // Trim leading/trailing - and _
    while (!result.empty() && (result.front() == '-' || result.front() == '_')) {
        result.erase(result.begin());
    }
    while (!result.empty() && (result.back() == '-' || result.back() == '_')) {
        result.pop_back();
    }
    // Enforce max length
    if (result.length() > 64) {
        result = result.substr(0, 64);
    }
    return result;
}

bool Sanitizer::isValidFilename(const std::string& filename) {
    if (filename.empty() || filename.length() > 128) {
        return false;
    }
    // No null bytes
    if (containsNullBytes(filename)) {
        utils::Logger::get_instance().warn("Null byte in filename");
        return false;
    }
    // No path traversal
    if (filename.find("..") != std::string::npos ||
        filename.find('/') != std::string::npos ||
        filename.find('\\') != std::string::npos) {
        utils::Logger::get_instance().warn("Path traversal attempt in filename: " + filename.substr(0, 50));
        return false;
    }
    // Character whitelist
    for (char c : filename) {
        if (!std::isalnum(static_cast<unsigned char>(c)) &&
            c != '.' && c != '_' && c != '-') {
            return false;
        }
    }
    // Must have an extension
    if (filename.find('.') == std::string::npos) {
        return false;
    }
    // Must not start with dot (hidden files)
    if (filename.front() == '.') {
        return false;
    }
    // Check extension whitelist
    return hasAllowedExtension(filename);
}

bool Sanitizer::hasAllowedExtension(const std::string& filename) {
    std::string lower = utils::StringUtils::to_lower(filename);
    for (const auto& ext : allowedExtensions_) {
        if (utils::StringUtils::ends_with(lower, ext)) {
            return true;
        }
    }
    return false;
}

bool Sanitizer::isCleanString(const std::string& s, size_t maxLen) {
    if (s.length() > maxLen) {
        return false;
    }
    if (containsNullBytes(s)) {
        return false;
    }
    if (containsControlChars(s)) {
        return false;
    }
    return true;
}

bool Sanitizer::isValidStatus(const std::string& s) {
    return s == "active" || s == "paused" || s == "completed" || s == "abandoned" || s == "archived" || s == "all";
}

bool Sanitizer::isValidPriority(const std::string& s) {
    return s == "high" || s == "medium" || s == "low";
}

std::string Sanitizer::safeDispositionName(const std::string& filename) {
    std::string safe;
    for (char c : filename) {
        if (std::isalnum(static_cast<unsigned char>(c)) ||
            c == '.' || c == '_' || c == '-') {
            safe += c;
        }
    }
    if (safe.empty()) {
        safe = "download";
    }
    return safe;
}

bool Sanitizer::containsNullBytes(const std::string& s) {
    return s.find('\0') != std::string::npos;
}

bool Sanitizer::containsControlChars(const std::string& s) {
    for (char c : s) {
        unsigned char uc = static_cast<unsigned char>(c);
        // Allow tab, newline, carriage return in content strings
        if (std::iscntrl(uc) && c != '\t' && c != '\n' && c != '\r') {
            return true;
        }
    }
    return false;
}

} // namespace security
