#pragma once

#include <string>

namespace security {

class Sanitizer {
public:
    // Safe filename for a Content-Disposition header: keep only [A-Za-z0-9._-],
    // falling back to "download". This is the only Sanitizer helper still in use
    // (the rest were project-tracker leftovers and have been removed).
    static std::string safeDispositionName(const std::string& filename);
};

} // namespace security
