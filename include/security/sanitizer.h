#pragma once

#include <string>
#include <vector>

namespace security {

class Sanitizer {
public:
    // Slug: [a-z0-9_-], 1-64 chars
    static bool isValidSlug(const std::string& slug);

    // Sanitize slug (lowercase, strip invalid chars)
    static std::string sanitizeSlug(const std::string& input);

    // Filename: [a-zA-Z0-9._-], 1-128 chars, whitelisted extension
    static bool isValidFilename(const std::string& filename);

    // Check file extension against whitelist
    static bool hasAllowedExtension(const std::string& filename);

    // Generic string: no null bytes, no control chars, max length
    static bool isCleanString(const std::string& s, size_t maxLen = 1024);

    // Status whitelist: active|paused|completed|abandoned
    static bool isValidStatus(const std::string& s);

    // Priority whitelist: high|medium|low
    static bool isValidPriority(const std::string& s);

    // Safe filename for Content-Disposition header
    static std::string safeDispositionName(const std::string& filename);

    // Check for null bytes
    static bool containsNullBytes(const std::string& s);

    // Check for control characters
    static bool containsControlChars(const std::string& s);

    // Load allowed extensions from config
    static void loadAllowedExtensions(const std::string& extensionList);

private:
    static std::vector<std::string> allowedExtensions_;
    static std::vector<std::string> defaultExtensions();
};

} // namespace security
