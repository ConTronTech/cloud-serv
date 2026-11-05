// Sign in with authentik (OIDC authorization code + PKCE), account linking and
// group-gated auto-creation. Errors always land back on the app as /#sso-error=<code>.
#include "routes/oidc.h"
#include "security/oidc.h"
#include "security/crypto.h"
#include "security/request_auth.h"
#include "core/config.h"
#include "utils/logger.h"
#include "routes/events.h"

#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include <ctime>
#include <map>
#include <mutex>

using json = nlohmann::json;

namespace routes {
namespace {

struct Pending { std::string nonce, verifier, redirectUri; int64_t linkUserId = 0; int64_t created = 0; };
std::mutex pendMx;
std::map<std::string, Pending> pending;          // state -> login attempt (10 min, max 500)

int64_t nowSec() { return static_cast<int64_t>(::time(nullptr)); }

void prune() {
    const int64_t cutoff = nowSec() - 600;
    for (auto it = pending.begin(); it != pending.end();) it = (it->second.created < cutoff) ? pending.erase(it) : std::next(it);
}

crow::response redirectTo(const std::string& where) {
    crow::response r(302);
    r.add_header("Location", where);
    r.add_header("Cache-Control", "no-store");
    return r;
}
crow::response fail(const std::string& code) { return redirectTo("/#sso-error=" + code); }

// Callback URL for whatever host the browser used (must also be registered at the IdP).
std::optional<std::string> callbackFor(const crow::request& req, const security::oidc::Config& cfg) {
    std::string host = req.get_header_value("Host");
    if (host.empty() || host.size() > 255) return std::nullopt;
    for (unsigned char ch : host) if (!(std::isalnum(ch) || ch == '.' || ch == '-' || ch == ':' || ch == '[' || ch == ']')) return std::nullopt;
    const bool tls = core::Config::get_instance().get_bool("env", "TLS_ENABLED", true);
    std::string uri = std::string(tls ? "https" : "http") + "://" + host + "/api/auth/oidc/callback";
    if (!cfg.redirectAllow.empty() && std::find(cfg.redirectAllow.begin(), cfg.redirectAllow.end(), uri) == cfg.redirectAllow.end())
        return std::nullopt;
    return uri;
}

std::string lower(std::string s) { for (auto& ch : s) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch))); return s; }

} // namespace

void registerOidcRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db, int sessionSeconds) {
    const auto cfg = security::oidc::loadConfig();
    int64_t defaultQuotaGb = core::Config::get_instance().get_int("env", "DEFAULT_STORAGE_QUOTA_GB", 0);
    if (cfg.enabled) utils::Logger::get_instance().info("OIDC: sign-in enabled (" + cfg.label + ", issuer " + cfg.issuer + ")");

    CROW_ROUTE(app, "/api/auth/oidc/config").methods(crow::HTTPMethod::GET)
    ([cfg]() { return http::jsonSuccess(json{{"enabled", cfg.enabled}, {"label", cfg.label}}.dump()); });

    CROW_ROUTE(app, "/api/auth/oidc/start").methods(crow::HTTPMethod::GET)
    ([&db, cfg](const crow::request& req) {
        if (!cfg.enabled) return fail("disabled");
        std::string mode = req.url_params.get("mode") ? req.url_params.get("mode") : "login";
        int64_t linkUser = 0;
        if (mode == "link") {
            auto uid = security::authenticateSession(req, db);
            if (!uid) return fail("not-signed-in");
            linkUser = *uid;
        }
        auto cb = callbackFor(req, cfg);
        if (!cb) return fail("bad-host");
        std::string err;
        auto d = security::oidc::discover(cfg, err);
        if (!d) { utils::Logger::get_instance().warn("OIDC " + err); return fail("idp-unreachable"); }

        Pending p{security::Crypto::randomHex(16), security::Crypto::randomHex(32), *cb, linkUser, nowSec()};
        std::string state = security::Crypto::randomHex(16);
        {
            std::lock_guard<std::mutex> lk(pendMx);
            prune();
            if (pending.size() >= 500) return fail("busy");
            pending[state] = p;
        }
        using security::oidc::urlEncode;
        std::string url = d->authorize + "?response_type=code&client_id=" + urlEncode(cfg.clientId) +
            "&redirect_uri=" + urlEncode(*cb) + "&scope=" + urlEncode("openid email profile") +
            "&state=" + state + "&nonce=" + p.nonce +
            "&code_challenge=" + security::oidc::pkceChallenge(p.verifier) + "&code_challenge_method=S256";
        return redirectTo(url);
    });

    CROW_ROUTE(app, "/api/auth/oidc/callback").methods(crow::HTTPMethod::GET)
    ([&db, cfg, sessionSeconds, defaultQuotaGb](const crow::request& req) {
        if (!cfg.enabled) return fail("disabled");
        if (req.url_params.get("error")) return fail("cancelled");
        const char* code = req.url_params.get("code");
        const char* state = req.url_params.get("state");
        if (!code || !state) return fail("bad-callback");
        Pending p;
        {
            std::lock_guard<std::mutex> lk(pendMx);
            auto it = pending.find(state);
            if (it == pending.end() || it->second.created < nowSec() - 600) { if (it != pending.end()) pending.erase(it); return fail("expired"); }
            p = it->second; pending.erase(it);       // single use
        }
        std::string err;
        auto d = security::oidc::discover(cfg, err);
        if (!d) return fail("idp-unreachable");
        auto c = security::oidc::exchangeCode(cfg, *d, code, p.verifier, p.redirectUri, p.nonce, err);
        if (!c) { utils::Logger::get_instance().warn("OIDC callback: " + err); return fail("login-failed"); }

        const std::string issuer = d->issuer;
        auto existing = db.userForIdentity(issuer, c->sub);

        // ---- Link mode: attach this identity to the signed-in account ----
        if (p.linkUserId) {
            if (existing && *existing != p.linkUserId) return fail("linked-elsewhere");
            if (!existing && !db.linkIdentity(p.linkUserId, issuer, c->sub, lower(c->email))) return fail("link-failed");
            utils::Logger::get_instance().info("OIDC: linked identity to user " + std::to_string(p.linkUserId));
            return redirectTo("/#sso-linked");
        }

        int64_t userId = 0;
        if (existing) {
            userId = *existing;
        } else {
            // New person: only members of the allowed group get an account.
            if (!cfg.allowedGroup.empty() &&
                std::find(c->groups.begin(), c->groups.end(), cfg.allowedGroup) == c->groups.end())
                return fail("not-allowed");
            std::string email = lower(c->email);
            if (email.empty() || email.find('@') == std::string::npos) return fail("no-email");
            // Never auto-attach to an existing local account by email (account takeover risk):
            // the owner links it from Settings instead.
            if (db.findUserByEmail(email)) return fail("email-in-use");
            std::string name = !c->name.empty() ? c->name : (!c->preferredUsername.empty() ? c->preferredUsername : email.substr(0, email.find('@')));
            if (name.size() > 64) name.resize(64);
            int64_t id = db.createUser(email, name, security::Crypto::hashPassword(security::Crypto::randomHex(32)));
            if (id < 0) return fail("create-failed");
            db.setLocalLogin(id, false);
            if (defaultQuotaGb > 0) db.setUserQuota(id, defaultQuotaGb * 1024 * 1024 * 1024);
            if (!db.linkIdentity(id, issuer, c->sub, email)) return fail("create-failed");
            utils::Logger::get_instance().info("OIDC: created account " + std::to_string(id) + " via SSO");
            notifyAdmins("users");
            userId = id;
        }

        auto user = db.findUserById(userId);
        if (!user) return fail("login-failed");
        if (user->status != "active") return fail("account-" + user->status);

        std::string token = security::Crypto::randomHex(32);
        db.createSession(userId, security::Crypto::sha256Hex(token), req.remote_ip_address, nowSec() + sessionSeconds);
        crow::response r = redirectTo("/#sso");
        r.add_header("Set-Cookie", security::sessionCookie(token, sessionSeconds));
        return r;
    });

    CROW_ROUTE(app, "/api/auth/identities").methods(crow::HTTPMethod::GET)
    ([&db, cfg](const crow::request& req) {
        auto userId = security::authenticateSession(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        json list = json::array();
        for (const auto& i : db.listIdentities(*userId))
            list.push_back({{"id", i.id}, {"provider", cfg.label}, {"email", i.email}, {"createdAt", i.created_at}});
        return http::jsonSuccess(json{{"identities", list}, {"localLogin", db.hasLocalLogin(*userId)},
                                      {"ssoEnabled", cfg.enabled}, {"label", cfg.label}}.dump());
    });

    CROW_ROUTE(app, "/api/auth/identities/<int>").methods(crow::HTTPMethod::DELETE)
    ([&db](const crow::request& req, int identityId) {
        auto userId = security::authenticateSession(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        if (!db.hasLocalLogin(*userId) && db.listIdentities(*userId).size() <= 1)
            return http::jsonError(409, "this is your only way to sign in");
        if (!db.unlinkIdentity(*userId, identityId)) return http::jsonError(404, "not found");
        return http::jsonSuccess(R"({"ok":true})");
    });
}

} // namespace routes
