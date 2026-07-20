#include "security/validator.h"
#include "utils/string_utils.h"
#include <stdexcept>

namespace security {

bool Validator::isBodySizeValid(size_t bodySize, size_t maxBytes) {
    return bodySize <= maxBytes;
}

bool Validator::hasJsonContentType(const std::string& contentType) {
    std::string lower = utils::StringUtils::to_lower(contentType);
    return lower.find("application/json") != std::string::npos;
}

bool Validator::hasTextContentType(const std::string& contentType) {
    std::string lower = utils::StringUtils::to_lower(contentType);
    return lower.find("text/plain") != std::string::npos ||
           lower.find("text/") != std::string::npos;
}

int Validator::safeStringToInt(const std::string& s, int defaultVal,
                                int minVal, int maxVal) {
    if (s.empty()) return defaultVal;
    try {
        int val = std::stoi(s);
        if (val < minVal) return minVal;
        if (val > maxVal) return maxVal;
        return val;
    } catch (const std::exception&) {
        return defaultVal;
    }
}

std::string Validator::safeParamString(const char* param, size_t maxLen) {
    if (!param) return "";
    std::string s(param);
    if (s.length() > maxLen) {
        s = s.substr(0, maxLen);
    }
    return s;
}

int Validator::safeParamInt(const char* param, int defaultVal,
                            int minVal, int maxVal) {
    if (!param) return defaultVal;
    return safeStringToInt(std::string(param), defaultVal, minVal, maxVal);
}

} // namespace security
