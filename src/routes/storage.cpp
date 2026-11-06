#include "routes/storage.h"
#include "routes/events.h"
#include "security/request_auth.h"
#include "utils/logger.h"

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace routes {
namespace {

constexpr int64_t kMaxRequestBytes = int64_t(16) * 1024 * 1024 * 1024 * 1024;   // 16 TB sanity cap

std::optional<int64_t> adminOnly(const crow::request& req, CloudDB& db, crow::response& err) {
    auto uid = security::authenticateSession(req, db);
    if (!uid) { err = http::jsonError(401, "unauthorized"); return std::nullopt; }
    auto u = db.findUserById(*uid);
    if (!u || u->role != "admin") { err = http::jsonError(403, "admin only"); return std::nullopt; }
    return uid;
}

json reqJson(CloudDB& db, const CloudDB::StorageRequest& r) {
    auto u = db.findUserById(r.user_id);
    json quota = (u && u->storage_quota_bytes) ? json(*u->storage_quota_bytes) : json(nullptr);
    return {{"id", r.id}, {"email", r.email}, {"displayName", r.display_name}, {"usedBytes", db.usage(r.user_id).first},
            {"quotaBytes", quota}, {"requestedBytes", r.requested_bytes}, {"uploadBytes", r.upload_bytes}, {"message", r.message},
            {"status", r.status}, {"createdAt", r.created_at}};
}

} // namespace

void registerStorageRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db) {
    CROW_ROUTE(app, "/api/storage-requests").methods(crow::HTTPMethod::POST)
    ([&db](const crow::request& req) {
        auto uid = security::authenticateSession(req, db);
        if (!uid) return http::jsonError(401, "unauthorized");
        json b = json::parse(req.body, nullptr, false);
        if (!b.is_object() || !b.contains("uploadBytes") || !b["uploadBytes"].is_number_integer())
            return http::jsonError(400, "uploadBytes (integer) required");
        const int64_t upload = b["uploadBytes"].get<int64_t>();
        auto u = db.findUserById(*uid);
        if (!u) return http::jsonError(401, "unauthorized");
        if (!u->storage_quota_bytes) return http::jsonError(409, "your storage is already unlimited");
        if (upload <= 0 || upload > kMaxRequestBytes) return http::jsonError(400, "invalid upload size");
        // The limit they'd need: what they use now + this upload, rounded up to the next 100 MB.
        const int64_t step = 100LL * 1024 * 1024;
        int64_t want = db.usage(*uid).first + upload;
        if (want <= *u->storage_quota_bytes) return http::jsonError(409, "that upload already fits");   // check before rounding
        want = ((want + step - 1) / step) * step;
        std::string msg;
        if (b.contains("message") && b["message"].is_string())
            for (unsigned char ch : b["message"].get<std::string>()) if (ch >= 0x20 && ch != 0x7f) msg += static_cast<char>(ch);
        if (msg.size() > 300) msg.resize(300);
        int64_t id = db.createStorageRequest(*uid, want, upload, msg);
        if (id < 0) return http::jsonError(500, "could not save request");
        utils::Logger::get_instance().info("storage: user " + std::to_string(*uid) + " asked for " + std::to_string(want) + " bytes");
        notifyAdmins("storage");
        return http::jsonSuccess(json{{"request", reqJson(db, *db.getStorageRequest(id))}}.dump());
    });

    CROW_ROUTE(app, "/api/storage-requests/mine").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req) {
        auto uid = security::authenticateSession(req, db);
        if (!uid) return http::jsonError(401, "unauthorized");
        auto r = db.latestStorageRequest(*uid);
        return http::jsonSuccess(json{{"request", r ? reqJson(db, *r) : json(nullptr)}}.dump());
    });

    CROW_ROUTE(app, "/api/admin/storage-requests").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req) {
        crow::response err;
        if (!adminOnly(req, db, err)) return err;
        json list = json::array();
        for (const auto& r : db.listPendingStorageRequests()) list.push_back(reqJson(db, r));
        return http::jsonSuccess(json{{"requests", list}}.dump());
    });

    CROW_ROUTE(app, "/api/admin/storage-requests/<int>/approve").methods(crow::HTTPMethod::POST)
    ([&db](const crow::request& req, int id) {
        crow::response err;
        auto adminId = adminOnly(req, db, err);
        if (!adminId) return err;
        auto r = db.getStorageRequest(id);
        if (!r || r->status != "pending") return http::jsonError(404, "no pending storage request with that id");
        int64_t grant = r->requested_bytes;
        json b = req.body.empty() ? json::object() : json::parse(req.body, nullptr, false);
        if (b.is_object() && b.contains("grantBytes")) {
            if (!b["grantBytes"].is_number_integer()) return http::jsonError(400, "grantBytes must be an integer");
            grant = b["grantBytes"].get<int64_t>();
        }
        if (grant <= 0 || grant > kMaxRequestBytes) return http::jsonError(400, "invalid amount");
        if (!db.decideStorageRequest(id, "approved", *adminId)) return http::jsonError(404, "no pending storage request with that id");
        db.setUserQuota(r->user_id, grant);
        utils::Logger::get_instance().info("storage: admin " + std::to_string(*adminId) + " set user " + std::to_string(r->user_id) + " quota to " + std::to_string(grant));
        notifyAdmins("storage"); notifyAdmins("users"); notifyUser(r->user_id, "quota");
        return http::jsonSuccess(json{{"ok", true}, {"quotaBytes", grant}}.dump());
    });

    CROW_ROUTE(app, "/api/admin/storage-requests/<int>/deny").methods(crow::HTTPMethod::POST)
    ([&db](const crow::request& req, int id) {
        crow::response err;
        auto adminId = adminOnly(req, db, err);
        if (!adminId) return err;
        auto r = db.getStorageRequest(id);
        if (!r || !db.decideStorageRequest(id, "denied", *adminId)) return http::jsonError(404, "no pending storage request with that id");
        notifyAdmins("storage"); notifyUser(r->user_id, "quota");
        return http::jsonSuccess(R"({"ok":true})");
    });
}

} // namespace routes
