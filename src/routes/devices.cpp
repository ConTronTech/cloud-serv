// Trusted devices + first-time encryption setup. The server never sees a device's
// private key or the DEK: it stores public keys and sealed (ECDH + AES-GCM) blobs only.
#include "routes/devices.h"
#include "security/request_auth.h"
#include "utils/logger.h"

#include <nlohmann/json.hpp>
#include <cctype>

using json = nlohmann::json;

namespace routes {
namespace {

constexpr int kMaxDevices = 50;
constexpr int kMaxPending = 5;

bool isB64ish(const std::string& v, size_t maxLen, bool allowDots) {
    if (v.empty() || v.size() > maxLen) return false;
    for (char ch : v)
        if (!(std::isalnum(static_cast<unsigned char>(ch)) || ch == '+' || ch == '/' || ch == '=' || ch == '-' || ch == '_' || (allowDots && ch == '.')))
            return false;
    return true;
}
std::string cleanName(std::string n) {
    std::string out;
    for (unsigned char ch : n) if (ch >= 0x20 && ch != 0x7f) out += static_cast<char>(ch);
    while (!out.empty() && out.back() == ' ') out.pop_back();
    while (!out.empty() && out.front() == ' ') out.erase(0, 1);
    if (out.size() > 80) out.resize(80);
    return out.empty() ? "Unnamed device" : out;
}
std::string str(const json& b, const char* k) { auto it = b.find(k); return (it != b.end() && it->is_string()) ? it->get<std::string>() : ""; }

json devJson(const CloudDB::Device& d) {
    return {{"id", d.id}, {"name", d.name}, {"status", d.status}, {"publicKey", d.public_key},
            {"createdAt", d.created_at}, {"lastUsedAt", d.last_used_at}, {"createdIp", d.created_ip}};
}

} // namespace

void registerDeviceRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db) {
    CROW_ROUTE(app, "/api/devices").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req) {
        auto uid = security::authenticateSession(req, db);
        if (!uid) return http::jsonError(401, "unauthorized");
        json list = json::array();
        for (const auto& d : db.listDevices(*uid)) list.push_back(devJson(d));
        return http::jsonSuccess(json{{"devices", list}}.dump());
    });

    CROW_ROUTE(app, "/api/devices").methods(crow::HTTPMethod::POST)
    ([&db](const crow::request& req) {
        auto uid = security::authenticateSession(req, db);
        if (!uid) return http::jsonError(401, "unauthorized");
        json b = json::parse(req.body, nullptr, false);
        if (!b.is_object()) return http::jsonError(400, "invalid json");
        const std::string pub = str(b, "publicKey"), wrapped = str(b, "wrappedDek");
        if (!isB64ish(pub, 300, false)) return http::jsonError(400, "invalid public key");
        if (!wrapped.empty() && !isB64ish(wrapped, 1024, true)) return http::jsonError(400, "invalid key material");
        if (db.countDevices(*uid, "") >= kMaxDevices) return http::jsonError(409, "too many devices: revoke some first");
        if (wrapped.empty() && db.countDevices(*uid, "pending") >= kMaxPending)
            return http::jsonError(409, "too many devices waiting for approval");
        int64_t id = db.createDevice(*uid, cleanName(str(b, "name")), pub, wrapped, req.remote_ip_address);
        if (id < 0) return http::jsonError(500, "could not save device");
        auto d = db.getDevice(*uid, id);
        utils::Logger::get_instance().info("devices: user " + std::to_string(*uid) + " added device " + std::to_string(id) +
                                           (wrapped.empty() ? " (pending approval)" : " (self-enrolled)"));
        return http::jsonSuccess(json{{"device", devJson(*d)}}.dump());
    });

    CROW_ROUTE(app, "/api/devices/<int>/key").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req, int id) {
        auto uid = security::authenticateSession(req, db);
        if (!uid) return http::jsonError(401, "unauthorized");
        auto d = db.getDevice(*uid, id);
        if (!d) return http::jsonError(404, "not found");
        if (d->status == "approved") db.touchDevice(*uid, id);
        return http::jsonSuccess(json{{"status", d->status}, {"wrappedDek", d->wrapped_dek}}.dump());
    });

    CROW_ROUTE(app, "/api/devices/<int>/approve").methods(crow::HTTPMethod::POST)
    ([&db](const crow::request& req, int id) {
        auto uid = security::authenticateSession(req, db);
        if (!uid) return http::jsonError(401, "unauthorized");
        json b = json::parse(req.body, nullptr, false);
        const std::string wrapped = b.is_object() ? str(b, "wrappedDek") : "";
        if (!isB64ish(wrapped, 1024, true)) return http::jsonError(400, "invalid key material");
        if (!db.approveDevice(*uid, id, wrapped)) return http::jsonError(404, "no pending device with that id");
        utils::Logger::get_instance().info("devices: user " + std::to_string(*uid) + " approved device " + std::to_string(id));
        return http::jsonSuccess(R"({"ok":true})");
    });

    CROW_ROUTE(app, "/api/devices/<int>").methods(crow::HTTPMethod::DELETE)
    ([&db](const crow::request& req, int id) {
        auto uid = security::authenticateSession(req, db);
        if (!uid) return http::jsonError(401, "unauthorized");
        if (!db.deleteDevice(*uid, id)) return http::jsonError(404, "not found");
        return http::jsonSuccess(R"({"ok":true})");
    });

    // First-time encryption setup for an account that has no key material yet
    // (e.g. created through SSO). Refused once any key exists, so it can't replace keys.
    CROW_ROUTE(app, "/api/keys/init").methods(crow::HTTPMethod::POST)
    ([&db](const crow::request& req) {
        auto uid = security::authenticateSession(req, db);
        if (!uid) return http::jsonError(401, "unauthorized");
        auto u = db.findUserById(*uid);
        if (!u) return http::jsonError(401, "unauthorized");
        if (!u->wrapped_dek.empty() || !u->wrapped_dek_recovery.empty())
            return http::jsonError(409, "encryption is already set up");
        json b = json::parse(req.body, nullptr, false);
        const std::string rec = b.is_object() ? str(b, "wrappedDekRecovery") : "";
        if (!isB64ish(rec, 1024, true) || rec.find('.') == std::string::npos) return http::jsonError(400, "invalid key material");
        if (!db.setUserKeys(*uid, u->kdf_salt, "", rec)) return http::jsonError(500, "could not save");
        return http::jsonSuccess(R"({"ok":true})");
    });
}

} // namespace routes
