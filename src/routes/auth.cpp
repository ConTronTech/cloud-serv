#include "routes/auth.h"
#include "security/crypto.h"
#include "security/rate_limiter.h"
#include "security/request_auth.h"
#include "utils/logger.h"
#include "core/config.h"

#include <nlohmann/json.hpp>
#include <ctime>
#include <regex>
#include <optional>

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

    static security::LoginThrottle loginThrottle;

    // Self-registration is gated by a shared invite code. Empty = disabled.
    const std::string inviteCode =
        core::Config::get_instance().get("env", "REGISTRATION_INVITE_CODE", "");
    // Quota newly-registered users start with (0/unset = unlimited). An admin
    // can raise/lower or clear it per-user afterwards via /api/admin/users.
    int64_t defaultQuotaGb = core::Config::get_instance().get_int("env", "DEFAULT_STORAGE_QUOTA_GB", 0);
    std::optional<int64_t> defaultQuotaBytes;
    if (defaultQuotaGb > 0) defaultQuotaBytes = defaultQuotaGb * 1024 * 1024 * 1024;

    // What a signed-in-but-not-allowed user is told. The notice + contact are
    // operator-configured so the appeal instructions can name a real address.
    const std::string removedNotice = core::Config::get_instance().get("env", "REMOVED_ACCOUNT_NOTICE",
        "Your data has been temporarily removed. To get it back, please appeal.");
    const std::string appealContact = core::Config::get_instance().get("env", "APPEAL_CONTACT", "");

    // ---- Register ----
    CROW_ROUTE(app, "/api/auth/register").methods(crow::HTTPMethod::POST)
    ([&db, sessionSeconds, inviteCode, defaultQuotaBytes](const crow::request& req) {
        json body; std::string err;
        if (!parseJsonObject(req, body, err)) return http::jsonError(400, err);

        std::string email = toLower(strField(body, "email"));
        std::string password = strField(body, "password");
        std::string displayName = strField(body, "displayName");
        if (displayName.empty()) displayName = email.substr(0, email.find('@'));

        if (!isValidEmail(email)) return http::jsonError(400, "invalid email");
        if (password.size() < 8) return http::jsonError(400, "password must be at least 8 characters");

        // Wrong invite code, registration disabled (empty config) and an already-taken
        // email all yield the identical generic 403, so none can be told apart (no
        // email enumeration). The (expensive) hash is only paid once the invite code checks out.
        bool inviteOk = !inviteCode.empty() &&
            security::Crypto::constantTimeEquals(strField(body, "inviteCode"), inviteCode);
        if (!inviteOk) return http::jsonError(403, "registration is not open");
        std::string pwHash = security::Crypto::hashPassword(password);
        int64_t userId = db.createUser(email, displayName, pwHash);
        if (userId < 0) return http::jsonError(403, "registration is not open");
        if (defaultQuotaBytes.has_value()) db.setUserQuota(userId, defaultQuotaBytes);

        // E2E key material — client-generated, opaque to us. Stored so we can hand
        // it back at login; without the user's password/recovery key it's useless.
        db.setUserKeys(userId, strField(body, "salt"),
                       strField(body, "wrappedDek"), strField(body, "wrappedDekRecovery"));

        // Issue a session token immediately so registration logs the user in.
        std::string token = security::Crypto::randomHex(32);
        int64_t expiresAt = static_cast<int64_t>(::time(nullptr)) + sessionSeconds;
        db.createSession(userId, security::Crypto::sha256Hex(token), req.remote_ip_address, expiresAt);

        json user = {{"id", userId}, {"email", email}, {"displayName", displayName}};
        auto res = http::jsonSuccess(json{{"token", token}, {"user", user}}.dump());
        res.add_header("Set-Cookie", security::sessionCookie(token, sessionSeconds));
        return res;
    });

    // ---- KDF salt for an email (needed client-side before login) ----
    // For unknown emails we return a decoy salt so registered/unregistered are
    // indistinguishable. The decoy is HMAC(serverSecret, email) — deterministic
    // per install but NOT client-computable, so an attacker who knows an email
    // cannot recompute it and detect that a real (different) salt was returned.
    const std::string decoyKey = db.serverSecret();
    CROW_ROUTE(app, "/api/auth/salt").methods(crow::HTTPMethod::GET)
    ([&db, decoyKey](const crow::request& req) {
        std::string email;
        if (const char* p = req.url_params.get("email")) email = toLower(p);
        auto salt = db.saltForEmail(email);
        std::string out = (salt && !salt->empty())
            ? *salt
            : security::Crypto::hmacSha256Hex(decoyKey, "cloud-serv-salt-v1|" + email).substr(0, 32);
        return http::jsonSuccess(json{{"salt", out}}.dump());
    });

    // ---- Login ----
    CROW_ROUTE(app, "/api/auth/login").methods(crow::HTTPMethod::POST)
    ([&db, sessionSeconds, removedNotice, appealContact](const crow::request& req) {
        json body; std::string err;
        if (!parseJsonObject(req, body, err)) return http::jsonError(400, err);

        std::string email = toLower(strField(body, "email"));
        std::string password = strField(body, "password");

        // Reject before the throttle/DB so attacker-sized emails are never stored.
        if (email.size() > 254) return http::jsonError(400, "invalid email");

        // Per-account backoff (independent of the per-IP limiter). On success this
        // reserves a slot that recordFailure/recordSuccess below must finalize.
        if (int wait = loginThrottle.acquire(email)) {
            auto res = http::jsonError(429, "too many failed attempts, try again later");
            res.add_header("Retry-After", std::to_string(wait));
            return res;
        }

        // The slot acquired above must be finalized exactly once. If anything below
        // throws before that, hand the slot back so the account isn't left stuck.
        struct SlotGuard {
            security::LoginThrottle& t; const std::string& key; bool done = false;
            ~SlotGuard() { if (!done) t.release(key); }
        } slot{loginThrottle, email};

        auto user = db.findUserByEmail(email);
        // Verify even when the user is missing, to keep timing ~constant and avoid
        // leaking which emails exist.
        static const std::string dummyHash =
            security::Crypto::hashPassword("cloud-serv-timing-dummy");
        bool ok = user
            ? security::Crypto::verifyPassword(password, user->password_hash)
            : (security::Crypto::verifyPassword(password, dummyHash), false);

        if (!user || !ok) {
            loginThrottle.recordFailure(email);
            slot.done = true;
            return http::jsonError(401, "invalid credentials");
        }
        loginThrottle.recordSuccess(email);
        slot.done = true;

        // Correct password, but the account isn't active: no session is minted.
        // Checked only after a real password match, so this can't be used to
        // probe account status without already knowing the password. The body
        // carries a machine-readable `code` plus the text to show the person.
        if (user->status == "removed") {
            json out = {{"error", "account data removed"}, {"code", "data_removed"},
                        {"notice", removedNotice}, {"appealContact", appealContact}};
            if (auto rec = db.getRemovalFor(user->id); rec && !rec->reason.empty()) out["reason"] = rec->reason;
            crow::response res(403, out.dump());
            res.set_header("Content-Type", "application/json");
            return res;
        }
        if (user->status != "active") {
            json out = {{"error", "account suspended"}, {"code", "suspended"}, {"appealContact", appealContact}};
            crow::response res(403, out.dump());
            res.set_header("Content-Type", "application/json");
            return res;
        }

        std::string token = security::Crypto::randomHex(32);
        int64_t expiresAt = static_cast<int64_t>(::time(nullptr)) + sessionSeconds;
        db.createSession(user->id, security::Crypto::sha256Hex(token), req.remote_ip_address, expiresAt);

        auto res = http::jsonSuccess(json{
            {"token", token}, {"user", user->toJson()},
            {"salt", user->kdf_salt}, {"wrappedDek", user->wrapped_dek}
        }.dump());
        res.add_header("Set-Cookie", security::sessionCookie(token, sessionSeconds));
        return res;
    });

    // ---- Me ----
    CROW_ROUTE(app, "/api/auth/me").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req) {
        // Session-only: the response carries the wrapped DEK + salt, which an API key must not reach.
        auto userId = security::authenticateSession(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        auto user = db.findUserById(*userId);
        if (!user) return http::jsonError(401, "unauthorized");
        const bool encDefault = core::Config::get_instance().get_bool("env", "FILES_ENCRYPT_DEFAULT", false);
        return http::jsonSuccess(json{
            {"user", user->toJson()},
            {"salt", user->kdf_salt}, {"wrappedDek", user->wrapped_dek},
            {"encryptFiles", db.getEncryptFiles(*userId).value_or(encDefault)}
        }.dump());
    });

    // ---- Preferences: {"encryptFiles": bool} ----
    // Only affects NEW uploads/folders. Existing files keep whatever they were stored as
    // (the client decrypts per file), so switching never breaks access to old files.
    CROW_ROUTE(app, "/api/auth/me/prefs").methods(crow::HTTPMethod::PATCH)
    ([&db](const crow::request& req) {
        auto userId = security::authenticateSession(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        json body = json::parse(req.body, nullptr, false);
        if (!body.is_object() || !body.contains("encryptFiles") || !body["encryptFiles"].is_boolean())
            return http::jsonError(400, "encryptFiles (boolean) required");
        const bool on = body["encryptFiles"].get<bool>();
        if (!db.setEncryptFiles(*userId, on)) return http::jsonError(500, "could not save");
        return http::jsonSuccess(json{{"encryptFiles", on}}.dump());
    });

    // ---- Logout (revoke current session token) ----
    CROW_ROUTE(app, "/api/auth/logout").methods(crow::HTTPMethod::POST)
    ([&db](const crow::request& req) {
        // Revoke whichever session token the client presented (header or cookie).
        std::string token = security::bearerToken(req.get_header_value("Authorization"));
        if (token.empty()) token = security::cookieSessionToken(req.get_header_value("Cookie"));
        if (!token.empty()) db.deleteSession(security::Crypto::sha256Hex(token));
        auto res = http::jsonSuccess(R"({"ok":true})");
        res.add_header("Set-Cookie", security::sessionCookie("", 0, true, true));
        return res;
    });

    // ---- Create API key (returned once, in full) ----
    CROW_ROUTE(app, "/api/auth/api-keys").methods(crow::HTTPMethod::POST)
    ([&db](const crow::request& req) {
        auto userId = security::authenticateSession(req, db);
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
        auto userId = security::authenticateSession(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        json keys = json::array();
        for (const auto& k : db.listApiKeys(*userId)) keys.push_back(k.toJson());
        return http::jsonSuccess(json{{"keys", keys}}.dump());
    });

    // ---- Revoke API key ----
    CROW_ROUTE(app, "/api/auth/api-keys/<int>").methods(crow::HTTPMethod::DELETE)
    ([&db](const crow::request& req, int keyId) {
        auto userId = security::authenticateSession(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        if (!db.revokeApiKey(*userId, keyId)) return http::jsonError(404, "key not found");
        return http::jsonSuccess(R"({"ok":true})");
    });
}

} // namespace routes
