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

std::string cookieSessionToken(const std::string& cookieHeader) {
    // Cookie header is "k1=v1; k2=v2; ...". Find the "session" cookie.
    const std::string key = "session=";
    size_t pos = 0;
    while (pos < cookieHeader.size()) {
        // Skip leading spaces / separators.
        while (pos < cookieHeader.size() && (cookieHeader[pos] == ' ' || cookieHeader[pos] == ';')) pos++;
        if (cookieHeader.compare(pos, key.size(), key) == 0) {
            size_t start = pos + key.size();
            size_t end = cookieHeader.find(';', start);
            if (end == std::string::npos) end = cookieHeader.size();
            return cookieHeader.substr(start, end - start);
        }
        pos = cookieHeader.find(';', pos);
        if (pos == std::string::npos) break;
    }
    return "";
}

std::string sessionCookie(const std::string& token, int maxAgeSeconds,
                          bool secure, bool clear) {
    std::string c = "session=";
    c += clear ? "" : token;
    c += "; Path=/; HttpOnly; SameSite=Strict";
    if (secure) c += "; Secure";
    c += "; Max-Age=" + std::to_string(clear ? 0 : maxAgeSeconds);
    return c;
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

    // Method 2: session bearer token (web client API calls after login).
    std::string token = bearerToken(req.get_header_value("Authorization"));
    if (!token.empty()) {
        return db.userForSession(Crypto::sha256Hex(token));
    }

    // Method 3: session cookie (media <video>/<img>/<audio> src, which can't
    // set an Authorization header). Same token, sent automatically same-origin.
    std::string cookieTok = cookieSessionToken(req.get_header_value("Cookie"));
    if (!cookieTok.empty()) {
        return db.userForSession(Crypto::sha256Hex(cookieTok));
    }

    return std::nullopt;
}

} // namespace security
