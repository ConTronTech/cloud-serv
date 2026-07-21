#include "security/sanitizer.h"
#include <cctype>

namespace security {

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

} // namespace security
