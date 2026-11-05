#include "routes/auth.h"
#include "security/crypto.h"
#include "security/rate_limiter.h"
#include "security/request_auth.h"
#include "utils/logger.h"
#include "core/config.h"

#include <nlohmann/json.hpp>
#include <cctype>
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

    // Anyone may ask for an account; it stays "pending" until an admin approves it.
    const bool requestsOn = core::Config::get_instance().get_bool("env", "REGISTRATION_REQUESTS", false);

    // What the register screen should offer.
    CROW_ROUTE(app, "/api/auth/signup-mode").methods(crow::HTTPMethod::GET)
    ([&db, requestsOn]() {
        return http::jsonSuccess(json{{"requests", requestsOn && db.countAdmins() > 0}}.dump());
    });

    // ---- Register ----
    CROW_ROUTE(app, "/api/auth/register").methods(crow::HTTPMethod::POST)
    ([&db, sessionSeconds, inviteCode, defaultQuotaBytes, requestsOn](const crow::request& req) {
        json body; std::string err;
        if (!parseJsonObject(req, body, err)) return http::jsonError(400, err);

        std::string email = toLower(strField(body, "email"));
        std::string password = strField(body, "password");
        std::string displayName = strField(body, "displayName");
        if (displayName.empty()) displayName = email.substr(0, email.find('@'));

        if (!isValidEmail(email)) return http::jsonError(400, "invalid email");
        if (password.size() < 8) return http::jsonError(400, "password must be at least 8 characters");

        // Three ways in: the legacy shared code from config, a one-time invite code from
        // the Admin page, or (no code at all) a sign-up request an admin must approve.
        // Wrong codes, closed registration and a taken email all give the same generic
        // answer, so none can be told apart (no email enumeration).
        const std::string code = strField(body, "inviteCode");
        bool legacyOk = !inviteCode.empty() && !code.empty() &&
            security::Crypto::constantTimeEquals(code, inviteCode);
        std::optional<int64_t> inviteId;
        if (!legacyOk && !code.empty()) {
            std::string norm;
            for (unsigned char ch : code) if (std::isalnum(ch)) norm += static_cast<char>(std::toupper(ch));
            if (!norm.empty() && norm.size() <= 64) inviteId = db.findUsableInvite(security::Crypto::sha256Hex(norm));
        }
        const bool viaInvite = legacyOk || inviteId.has_value();
        const bool asRequest = !viaInvite && code.empty() && requestsOn;
        if (!viaInvite && !asRequest) return http::jsonError(403, "registration is not open");
        if (asRequest) {
            // Requests need someone to approve them (and the very first account would
            // otherwise be auto-promoted to admin), and the queue is capped.
            if (db.countAdmins() == 0) return http::jsonError(403, "registration is not open");
            if (db.countUsersWithStatus("pending") >= 25)
                return http::jsonError(429, "too many sign-up requests waiting; try again later");
        }
        std::string pwHash = security::Crypto::hashPassword(password);
        int64_t userId = db.createUser(email, displayName, pwHash);
        if (userId < 0) {
            if (asRequest) { auto r = http::jsonSuccess(R"({"pending":true})"); r.code = 202; return r; }   // same answer as a real request
            return http::jsonError(403, "registration is not open");
        }
        if (asRequest) db.setUserStatus(userId, "pending");
        if (inviteId && !db.consumeInvite(*inviteId, userId)) {   // lost a race for the same code
            db.setUserStatus(userId, "pending");
            db.deletePendingUser(userId);
            return http::jsonError(403, "registration is not open");
        }
        if (defaultQuotaBytes.has_value()) db.setUserQuota(userId, defaultQuotaBytes);

        // E2E key material — client-generated, opaque to us. Stored so we can hand
        // it back at login; without the user's password/recovery key it's useless.
        db.setUserKeys(userId, strField(body, "salt"),
                       strField(body, "wrappedDek"), strField(body, "wrappedDekRecovery"));

        if (asRequest) {
            std::string note;
            for (unsigned char ch : strField(body, "note")) if (ch >= 0x20 && ch != 0x7f) note += static_cast<char>(ch);
            if (note.size() > 300) note.resize(300);
            db.setSignupInfo(userId, req.remote_ip_address, note);
            utils::Logger::get_instance().info("signup: request from " + email + " waiting for approval");
            auto r = http::jsonSuccess(R"({"pending":true})"); r.code = 202; return r;
        }

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
        if (user->status == "pending") {
            json out = {{"error", "your sign-up is waiting for an admin to approve it"}, {"code", "pending"}};
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
            {"wrappedDekRecovery", user->wrapped_dek_recovery},
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
        if (!body.is_object()) return http::jsonError(400, "invalid json");
        const bool hasEnc = body.contains("encryptFiles"), hasName = body.contains("displayName");
        if (!hasEnc && !hasName) return http::jsonError(400, "nothing to change");
        if (hasEnc && !body["encryptFiles"].is_boolean()) return http::jsonError(400, "encryptFiles (boolean) required");
        std::string name;
        if (hasName) {
            if (!body["displayName"].is_string()) return http::jsonError(400, "invalid display name");
            name = body["displayName"].get<std::string>();
            while (!name.empty() && name.back() == ' ') name.pop_back();
            while (!name.empty() && name.front() == ' ') name.erase(0, 1);
            bool ctl = false; for (unsigned char ch : name) if (ch < 0x20 || ch == 0x7f) ctl = true;
            if (name.empty() || name.size() > 64 || ctl) return http::jsonError(400, "display name must be 1-64 characters");
        }
        json out = json::object();
        if (hasEnc) {
            const bool on = body["encryptFiles"].get<bool>();
            if (!db.setEncryptFiles(*userId, on)) return http::jsonError(500, "could not save");
            out["encryptFiles"] = on;
        }
        if (hasName) {
            if (!db.setDisplayName(*userId, name)) return http::jsonError(500, "could not save");
            out["displayName"] = name;
        }
        return http::jsonSuccess(out.dump());
    });

    // ---- Change password (E2E-aware) ----
    // The browser proves the current password (its derived auth key), and sends the new
    // auth key, a fresh KDF salt and the DEK re-wrapped under the new password. Files and
    // notes keep working because the DEK itself never changes. Other devices are signed out.
    CROW_ROUTE(app, "/api/auth/password").methods(crow::HTTPMethod::POST)
    ([&db](const crow::request& req) {
        auto userId = security::authenticateSession(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        json body; std::string err;
        if (!parseJsonObject(req, body, err)) return http::jsonError(400, err);
        const std::string cur = strField(body, "currentPassword"), next = strField(body, "newPassword");
        const std::string salt = strField(body, "salt"), wrapped = strField(body, "wrappedDek");
        auto isHex = [](const std::string& v) { for (char ch : v) if (!std::isxdigit(static_cast<unsigned char>(ch))) return false; return true; };
        auto isB64ish = [](const std::string& v) {
            for (char ch : v) if (!(std::isalnum(static_cast<unsigned char>(ch)) || ch == '+' || ch == '/' || ch == '=' || ch == '.')) return false;
            return true; };
        if (next.size() < 8 || next.size() > 256) return http::jsonError(400, "invalid new password");
        if (salt.size() < 16 || salt.size() > 128 || !isHex(salt)) return http::jsonError(400, "invalid salt");
        if (wrapped.empty() || wrapped.size() > 1024 || !isB64ish(wrapped) || wrapped.find('.') == std::string::npos)
            return http::jsonError(400, "invalid key material");
        auto user = db.findUserById(*userId);
        if (!user) return http::jsonError(401, "unauthorized");
        if (!security::Crypto::verifyPassword(cur, user->password_hash))
            return http::jsonError(403, "current password is wrong");
        if (!db.setPasswordAndKeys(*userId, security::Crypto::hashPassword(next), salt, wrapped))
            return http::jsonError(500, "could not save");
        std::string token = security::bearerToken(req.get_header_value("Authorization"));
        if (token.empty()) token = security::cookieSessionToken(req.get_header_value("Cookie"));
        int signedOut = db.deleteOtherSessions(*userId, security::Crypto::sha256Hex(token));
        return http::jsonSuccess(json{{"ok", true}, {"otherSessionsSignedOut", signedOut}}.dump());
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
