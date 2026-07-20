#include "routes/auth.h"
#include "security/crypto.h"
#include "security/request_auth.h"
#include "utils/logger.h"

#include <nlohmann/json.hpp>
#include <ctime>
#include <regex>

using json = nlohmann::json;

namespace routes {

namespace {

bool isValidEmail(const std::string& email) {
    static const std::regex re(R"(^[^@\s]+@[^@\s]+\.[^@\s]+$)");
    return email.size() <= 254 && std::regex_match(email, re);
}

std::string toLower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Parse a JSON object body; returns false (and sets err) on malformed input.
bool parseJsonObject(const crow::request& req, json& out, std::string& err) {
    out = json::parse(req.body, nullptr, false);
    if (out.is_discarded() || !out.is_object()) {
        err = "invalid json";
        return false;
    }
    return true;
}

std::string strField(const json& j, const char* key) {
    if (j.contains(key) && j[key].is_string()) return j[key].get<std::string>();
    return "";
}

} // namespace

void registerAuthRoutes(crow::App<http::SecurityMiddleware>& app,
                        CloudDB& db, int sessionSeconds) {

    // ---- Register ----
    CROW_ROUTE(app, "/api/auth/register").methods(crow::HTTPMethod::POST)
    ([&db, sessionSeconds](const crow::request& req) {
        json body; std::string err;
        if (!parseJsonObject(req, body, err)) return http::jsonError(400, err);

        std::string email = toLower(strField(body, "email"));
        std::string password = strField(body, "password");
        std::string displayName = strField(body, "displayName");
        if (displayName.empty()) displayName = email.substr(0, email.find('@'));

        if (!isValidEmail(email)) return http::jsonError(400, "invalid email");
        if (password.size() < 8) return http::jsonError(400, "password must be at least 8 characters");

        int64_t userId = db.createUser(email, displayName, security::Crypto::hashPassword(password));
        if (userId < 0) return http::jsonError(409, "email already registered");

        // Issue a session token immediately so registration logs the user in.
        std::string token = security::Crypto::randomHex(32);
        int64_t expiresAt = static_cast<int64_t>(::time(nullptr)) + sessionSeconds;
        db.createSession(userId, security::Crypto::sha256Hex(token), req.remote_ip_address, expiresAt);

        json user = {{"id", userId}, {"email", email}, {"displayName", displayName}};
        auto res = http::jsonSuccess(json{{"token", token}, {"user", user}}.dump());
        res.add_header("Set-Cookie", security::sessionCookie(token, sessionSeconds));
        return res;
    });

    // ---- Login ----
    CROW_ROUTE(app, "/api/auth/login").methods(crow::HTTPMethod::POST)
    ([&db, sessionSeconds](const crow::request& req) {
        json body; std::string err;
        if (!parseJsonObject(req, body, err)) return http::jsonError(400, err);

        std::string email = toLower(strField(body, "email"));
        std::string password = strField(body, "password");

        auto user = db.findUserByEmail(email);
        // Verify even when the user is missing, to keep timing ~constant and avoid
        // leaking which emails exist.
        static const std::string dummyHash =
            security::Crypto::hashPassword("cloud-serv-timing-dummy");
        bool ok = user
            ? security::Crypto::verifyPassword(password, user->password_hash)
            : (security::Crypto::verifyPassword(password, dummyHash), false);

        if (!user || !ok) return http::jsonError(401, "invalid credentials");

        std::string token = security::Crypto::randomHex(32);
        int64_t expiresAt = static_cast<int64_t>(::time(nullptr)) + sessionSeconds;
        db.createSession(user->id, security::Crypto::sha256Hex(token), req.remote_ip_address, expiresAt);

        auto res = http::jsonSuccess(json{{"token", token}, {"user", user->toJson()}}.dump());
        res.add_header("Set-Cookie", security::sessionCookie(token, sessionSeconds));
        return res;
    });

    // ---- Me ----
    CROW_ROUTE(app, "/api/auth/me").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        auto user = db.findUserById(*userId);
        if (!user) return http::jsonError(401, "unauthorized");
        return http::jsonSuccess(json{{"user", user->toJson()}}.dump());
    });

    // ---- Logout (revoke current session token) ----
    CROW_ROUTE(app, "/api/auth/logout").methods(crow::HTTPMethod::POST)
    ([&db](const crow::request& req) {
        // Revoke whichever session token the client presented (header or cookie).
        std::string token = security::bearerToken(req.get_header_value("Authorization"));
        if (token.empty()) token = security::cookieSessionToken(req.get_header_value("Cookie"));
        if (!token.empty()) db.deleteSession(security::Crypto::sha256Hex(token));
        auto res = http::jsonSuccess(R"({"ok":true})");
        res.add_header("Set-Cookie", security::sessionCookie("", 0, false, true));
        return res;
    });

    // ---- Create API key (returned once, in full) ----
    CROW_ROUTE(app, "/api/auth/api-keys").methods(crow::HTTPMethod::POST)
    ([&db](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        std::string name;
        if (!req.body.empty()) {
            json body = json::parse(req.body, nullptr, false);
            if (body.is_object()) name = strField(body, "name");
        }

        std::string fullKey = "csk_" + security::Crypto::randomHex(24);
        std::string prefix = fullKey.substr(0, 12);
        int64_t keyId = db.createApiKey(*userId, name, prefix,
                                        security::Crypto::sha256Hex(fullKey));
        if (keyId < 0) return http::jsonError(500, "could not create key");

        json info = {{"id", keyId}, {"name", name}, {"prefix", prefix}};
        // "key" is the only time the full secret is ever shown.
        return http::jsonSuccess(json{{"key", fullKey}, {"info", info}}.dump());
    });

    // ---- List API keys (prefixes only, never the secret) ----
    CROW_ROUTE(app, "/api/auth/api-keys").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        json keys = json::array();
        for (const auto& k : db.listApiKeys(*userId)) keys.push_back(k.toJson());
        return http::jsonSuccess(json{{"keys", keys}}.dump());
    });

    // ---- Revoke API key ----
    CROW_ROUTE(app, "/api/auth/api-keys/<int>").methods(crow::HTTPMethod::DELETE)
    ([&db](const crow::request& req, int keyId) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        if (!db.revokeApiKey(*userId, keyId)) return http::jsonError(404, "key not found");
        return http::jsonSuccess(R"({"ok":true})");
    });
}

} // namespace routes
