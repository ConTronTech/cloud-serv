#pragma once

#include <string>

// Forward declare crow types to avoid header dependency
namespace crow { class request; }

namespace security {

class Validator {
public:
    // Body size check
    static bool isBodySizeValid(size_t bodySize, size_t maxBytes);

    // Content-Type checks
    static bool hasJsonContentType(const std::string& contentType);
    static bool hasTextContentType(const std::string& contentType);

    // Safe integer parsing from string (no exceptions)
    static int safeStringToInt(const std::string& s, int defaultVal = 0,
                               int minVal = 0, int maxVal = 100000);

    // Safe string param (null check + length limit)
    static std::string safeParamString(const char* param, size_t maxLen = 256);

    // Safe int param
    static int safeParamInt(const char* param, int defaultVal = 0,
                            int minVal = 0, int maxVal = 100000);
};

} // namespace security
