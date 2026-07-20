#pragma once

#include <string>
#include <cstdint>
#include <optional>

// Forward declare to avoid pulling crow into every header.
namespace crow { struct request; }
class CloudDB;

namespace security {

// Authenticate an incoming request against the DB. Accepts either:
//   * X-API-Key: <key>              (programmatic / mobile / CLI clients)
//   * Authorization: Bearer <token> (web session after login)
// Returns the owning user id, or std::nullopt if neither is valid.
std::optional<int64_t> authenticateRequest(const crow::request& req, CloudDB& db);

// Extract the token from an "Authorization: Bearer <token>" header value.
// Returns empty string if the header is missing or malformed.
std::string bearerToken(const std::string& authHeader);

// Extract the "session=<token>" value from a Cookie header. Empty if absent.
std::string cookieSessionToken(const std::string& cookieHeader);

// Build the Set-Cookie value that stores a session token, or clears it when
// `clear` is true. HttpOnly + SameSite=Strict; Secure is added when `secure`.
std::string sessionCookie(const std::string& token, int maxAgeSeconds,
                          bool secure = false, bool clear = false);

} // namespace security
