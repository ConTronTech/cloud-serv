#include "routes/admin.h"
#include "security/request_auth.h"
#include "utils/logger.h"

#include <nlohmann/json.hpp>
#include <filesystem>
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

std::string lowered(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// The irreversible actions require the caller to restate the account's exact
// email, so a mistyped id, a replayed request or a stray click can't destroy
// the wrong account.
bool confirmMatches(const json& body, const std::string& expectedEmail) {
    return body.contains("confirmEmail") && body["confirmEmail"].is_string() &&
           lowered(body["confirmEmail"].get<std::string>()) == lowered(expectedEmail);
}

} // namespace

void registerAdminRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db,
                         FileStore& store, const std::string& backupRoot) {

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
            // Only an ACTIVE admin counts toward "the last admin": demoting one who
            // is already suspended/removed can't lock the system out.
            if (target->role == "admin" && target->status == "active" && role != "admin" &&
                db.countAdmins() <= 1)
                return http::jsonError(409, "cannot remove the last admin");
            if (!db.setUserRole(targetId, role)) return http::jsonError(500, "could not update role");
        }

        if (body.contains("suspended")) {
            if (!body["suspended"].is_boolean()) return http::jsonError(400, "suspended must be a boolean");
            bool suspended = body["suspended"].get<bool>();
            // A removed account leaves that state only via restore or wipe; the
            // suspend toggle must never quietly reactivate it.
            if (target->status == "removed")
                return http::jsonError(409, "account is removed; restore or wipe it instead");
            // Re-read role in case it was just changed above in this same request.
            auto fresh = db.findUserById(targetId);
            if (suspended && fresh && fresh->role == "admin" && fresh->status == "active" &&
                db.countAdmins() <= 1)
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

    // ---- Backup + temp remove (the account STAYS; its data goes) ----
    CROW_ROUTE(app, "/api/admin/users/<int>/remove").methods(crow::HTTPMethod::POST)
    ([&db, &store, backupRoot](const crow::request& req, int targetId) {
        crow::response err;
        auto adminId = requireAdmin(req, db, err);
        if (!adminId) return err;

        // Optional {"reason": "..."} — shown to the account's owner at sign-in.
        std::string reason;
        if (!req.body.empty()) {
            json body; std::string perr;
            if (!parseJsonObject(req, body, perr)) return http::jsonError(400, perr);
            if (body.contains("reason")) {
                if (!body["reason"].is_string()) return http::jsonError(400, "reason must be a string");
                reason = body["reason"].get<std::string>();
                if (reason.size() > 500) return http::jsonError(400, "reason is too long (max 500)");
                for (unsigned char c : reason)
                    if (c < 0x20 || c == 0x7f) return http::jsonError(400, "reason contains control characters");
            }
        }

        auto r = db.removeUser(targetId, *adminId, backupRoot, reason,
            [&store, targetId](const std::string& dest) { return store.stageUserDir(targetId, dest); });
        if (!r.ok) return http::jsonError(r.status, r.error);

        // The live blob dir goes only after the DB commit; the backup holds hard
        // links (or copies) so the bytes survive. A failure here just leaves an
        // unreferenced directory, so report it rather than fail the removal.
        bool storageRemoved = store.removeUserDir(targetId);
        if (!storageRemoved)
            utils::Logger::get_instance().warn("admin remove: live storage dir for user " +
                                               std::to_string(targetId) + " could not be deleted");
        return http::jsonSuccess(json{{"removedUserId", targetId}, {"status", "removed"},
                                      {"storageRemoved", storageRemoved}}.dump());
    });

    // ---- Restore a removed account's data from its backup ----
    CROW_ROUTE(app, "/api/admin/users/<int>/restore").methods(crow::HTTPMethod::POST)
    ([&db, &store, backupRoot](const crow::request& req, int targetId) {
        crow::response err;
        if (!requireAdmin(req, db, err)) return err;

        auto r = db.restoreUser(targetId, backupRoot,
            [&store, targetId](const std::string& src, const std::vector<std::string>& keys) {
                return store.restoreBlobs(targetId, src, keys); },
            [&store, targetId](const std::vector<std::string>& keys) { store.removeBlobs(targetId, keys); });
        if (!r.ok) return http::jsonError(r.status, r.error);
        return http::jsonSuccess(json{{"restoredUserId", targetId}, {"status", "active"},
                                      {"folders", r.nFolders}, {"files", r.nFiles},
                                      {"notes", r.nNotes}}.dump());
    });

    // ---- Which accounts are removed (and what their backups hold) ----
    CROW_ROUTE(app, "/api/admin/removed-users").methods(crow::HTTPMethod::GET)
    ([&db, backupRoot](const crow::request& req) {
        namespace fs = std::filesystem;
        crow::response err;
        if (!requireAdmin(req, db, err)) return err;
        std::error_code ec;
        const fs::path root = fs::weakly_canonical(backupRoot, ec);
        json out = json::array();
        for (const auto& t : db.listRemovedUsers()) {
            json j = t.toJson();
            // Backup size, for capacity planning. Only walked when the recorded
            // path really is a direct child of the backup root.
            int64_t bytes = -1;
            std::error_code e2;
            fs::path dir = fs::weakly_canonical(t.backup_path, e2);
            if (!ec && !e2 && !dir.empty() && dir != root && dir.parent_path() == root && fs::is_directory(dir, e2)) {
                bytes = 0;
                for (const auto& f : fs::recursive_directory_iterator(dir, e2)) {
                    std::error_code e3;
                    if (f.is_regular_file(e3)) bytes += static_cast<int64_t>(f.file_size(e3));
                }
            }
            j["backupBytes"] = bytes >= 0 ? json(bytes) : json(nullptr);
            out.push_back(std::move(j));
        }
        return http::jsonSuccess(json{{"removedUsers", out}}.dump());
    });

    // ---- Permanent wipe (any account; a removed one also loses its backup) ----
    CROW_ROUTE(app, "/api/admin/users/<int>/wipe").methods(crow::HTTPMethod::POST)
    ([&db, &store, backupRoot](const crow::request& req, int targetId) {
        crow::response err;
        auto adminId = requireAdmin(req, db, err);
        if (!adminId) return err;

        json body; std::string perr;
        if (!parseJsonObject(req, body, perr)) return http::jsonError(400, perr);
        auto target = db.findUserById(targetId);
        if (!target) return http::jsonError(404, "user not found");
        if (!confirmMatches(body, target->email))
            return http::jsonError(400, "confirmEmail must exactly match the account's email");

        auto r = db.wipeUser(targetId, *adminId, backupRoot);
        if (!r.ok) return http::jsonError(r.status, r.error);
        bool storageRemoved = store.removeUserDir(targetId);
        if (!storageRemoved)
            utils::Logger::get_instance().warn("admin wipe: storage dir for user " +
                                               std::to_string(targetId) + " could not be deleted");
        return http::jsonSuccess(json{{"wiped", true}, {"storageRemoved", storageRemoved},
                                      {"backupRemoved", r.backupRemoved}}.dump());
    });
}

} // namespace routes
