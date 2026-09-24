#include "routes/admin.h"
#include "security/request_auth.h"

#include <nlohmann/json.hpp>
#include <optional>

using json = nlohmann::json;

namespace routes {

namespace {

bool parseJsonObject(const crow::request& req, json& out, std::string& err) {
    out = json::parse(req.body, nullptr, false);
    if (out.is_discarded() || !out.is_object()) {
        err = "invalid json";
        return false;
    }
    return true;
}

// Session-only, admin-only. Returns the caller's own user id, or nullopt with
// the response already set to the right error (401 vs 403) via `err`.
std::optional<int64_t> requireAdmin(const crow::request& req, CloudDB& db, crow::response& err) {
    auto userId = security::authenticateSession(req, db);
    if (!userId) { err = http::jsonError(401, "unauthorized"); return std::nullopt; }
    auto caller = db.findUserById(*userId);
    if (!caller || caller->role != "admin") { err = http::jsonError(403, "admin only"); return std::nullopt; }
    return userId;
}

} // namespace

void registerAdminRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db) {

    // ---- List every account ----
    CROW_ROUTE(app, "/api/admin/users").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req) {
        crow::response err;
        if (!requireAdmin(req, db, err)) return err;

        json users = json::array();
        for (const auto& u : db.listAllUsers()) {
            auto [bytes, count] = db.usage(u.id);
            users.push_back(u.toAdminJson(bytes, count));
        }
        return http::jsonSuccess(json{{"users", users}}.dump());
    });

    // ---- Update role / suspension / quota ----
    CROW_ROUTE(app, "/api/admin/users/<int>").methods(crow::HTTPMethod::PATCH)
    ([&db](const crow::request& req, int targetId) {
        crow::response err;
        auto adminId = requireAdmin(req, db, err);
        if (!adminId) return err;

        json body; std::string perr;
        if (!parseJsonObject(req, body, perr)) return http::jsonError(400, perr);

        auto target = db.findUserById(targetId);
        if (!target) return http::jsonError(404, "user not found");

        if (body.contains("role")) {
            if (!body["role"].is_string()) return http::jsonError(400, "role must be a string");
            std::string role = body["role"].get<std::string>();
            if (role != "user" && role != "admin") return http::jsonError(400, "role must be 'user' or 'admin'");
            // Refuse a change that would leave zero admins (e.g. demoting the
            // only admin, including an admin demoting themselves).
            if (target->role == "admin" && role != "admin" && db.countAdmins() <= 1)
                return http::jsonError(409, "cannot remove the last admin");
            if (!db.setUserRole(targetId, role)) return http::jsonError(500, "could not update role");
        }

        if (body.contains("suspended")) {
            if (!body["suspended"].is_boolean()) return http::jsonError(400, "suspended must be a boolean");
            bool suspended = body["suspended"].get<bool>();
            // Re-read role in case it was just changed above in this same request.
            auto fresh = db.findUserById(targetId);
            if (suspended && fresh && fresh->role == "admin" && db.countAdmins() <= 1)
                return http::jsonError(409, "cannot suspend the last admin");
            if (!db.setUserSuspended(targetId, suspended)) return http::jsonError(500, "could not update status");
        }

        if (body.contains("storageQuotaBytes")) {
            const auto& q = body["storageQuotaBytes"];
            std::optional<int64_t> quota;
            if (q.is_null()) {
                quota = std::nullopt;  // unlimited
            } else if (q.is_number_integer() && q.get<int64_t>() >= 0) {
                quota = q.get<int64_t>();
            } else {
                return http::jsonError(400, "storageQuotaBytes must be a non-negative integer or null");
            }
            if (!db.setUserQuota(targetId, quota)) return http::jsonError(500, "could not update quota");
        }

        auto updated = db.findUserById(targetId);
        if (!updated) return http::jsonError(404, "user not found");
        auto [bytes, count] = db.usage(updated->id);
        return http::jsonSuccess(updated->toAdminJson(bytes, count).dump());
    });
}

} // namespace routes
