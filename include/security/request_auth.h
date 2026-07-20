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

} // namespace security
