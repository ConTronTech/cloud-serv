#include "security/request_auth.h"
#include "security/crypto.h"
#include "db/database.h"
#include <crow.h>

namespace security {

std::string bearerToken(const std::string& authHeader) {
    const std::string prefix = "Bearer ";
    if (authHeader.size() <= prefix.size()) return "";
    if (authHeader.compare(0, prefix.size(), prefix) != 0) return "";
    return authHeader.substr(prefix.size());
}

std::optional<int64_t> authenticateRequest(const crow::request& req, CloudDB& db) {
    // Method 1: API key header (agents / mobile / scripts).
    std::string apiKey = req.get_header_value("X-API-Key");
    if (!apiKey.empty()) {
        auto userId = db.userForApiKey(Crypto::sha256Hex(apiKey));
        if (userId) return userId;
        // A present-but-invalid key should not fall through to session auth.
        return std::nullopt;
    }

    // Method 2: session bearer token (web client after login).
    std::string token = bearerToken(req.get_header_value("Authorization"));
    if (!token.empty()) {
        return db.userForSession(Crypto::sha256Hex(token));
    }

    return std::nullopt;
}

} // namespace security
