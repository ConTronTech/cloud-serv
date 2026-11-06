#include "routes/fs.h"
#include "security/request_auth.h"

#include <nlohmann/json.hpp>
#include <string>
#include <algorithm>

#include "routes/events.h"
#include "routes/tree_helpers.h"
#include "storage/user_lock.h"
#include <mutex>
using json = nlohmann::json;

namespace routes {

namespace {

bool anyControlChar(const std::string& s) {
    for (unsigned char c : s) if (c < 0x20 || c == 0x7f) return true;
    return false;
}

// A folder/file display name: no path separators, control chars, or dot-dirs.
bool validName(const std::string& name) {
    if (name.empty() || name.size() > 255) return false;
    if (anyControlChar(name)) return false;
    if (name.find('/') != std::string::npos || name.find('\\') != std::string::npos) return false;
    return name != "." && name != "..";
}

// Opaque "iv.ct" base64 blob for an E2E-encrypted name (see files.cpp).
bool validEncName(const std::string& s) {
    if (s.empty() || s.size() > 4096) return false;
    for (unsigned char c : s) {
        bool okChar = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '.';
        if (!okChar) return false;
    }
    return true;
}

std::string strField(const json& j, const char* key) {
    if (j.contains(key) && j[key].is_string()) return j[key].get<std::string>();
    return "";
}

int64_t intField(const json& j, const char* key, int64_t def) {
    if (j.contains(key) && j[key].is_number_integer()) return j[key].get<int64_t>();
    return def;
}

} // namespace

void registerFsRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db, FileStore& store, TreeStore& tree) {

    // ---- List a directory ----
    CROW_ROUTE(app, "/api/fs").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        int64_t folderId = 0;
        if (const char* p = req.url_params.get("folder")) {
            try { folderId = std::stoll(p); } catch (...) { folderId = 0; }
        }

        json folderJson = nullptr;
        json breadcrumbs = json::array();
        if (folderId != 0) {
            auto f = db.getFolder(*userId, folderId);
            if (!f) return http::jsonError(404, "folder not found");
            folderJson = f->toJson();
            for (const auto& a : db.folderPath(*userId, folderId)) breadcrumbs.push_back(a.toJson());
        }

        json folders = json::array();
        for (const auto& f : db.listFolders(*userId, folderId)) folders.push_back(f.toJson());
        json files = json::array();
        for (const auto& f : db.listFiles(*userId, folderId)) files.push_back(f.toJson());

        return http::jsonSuccess(json{
            {"folder", folderJson},
            {"breadcrumbs", breadcrumbs},
            {"folders", folders},
            {"files", files}
        }.dump());
    });

    // ---- Create folder ----
    CROW_ROUTE(app, "/api/folders").methods(crow::HTTPMethod::POST)
    ([&db, &tree](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        json body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.is_object()) return http::jsonError(400, "invalid json");

        if (auto acct = tree::account(db, tree, *userId)) {
            if (!strField(body, "encName").empty()) return tree::noEncryption();
            std::string name = strField(body, "name");
            if (!validName(name) || !TreeStore::validUserName(name)) return http::jsonError(400, "invalid folder name");
            int64_t parentId = intField(body, "parentId", 0);
            std::lock_guard<std::mutex> lk(storage::userLock(*userId));
            if (!db.folderExists(*userId, parentId)) return http::jsonError(400, "folder not found");
            auto rel = tree::folderRel(db, *userId, parentId);
            if (!rel) return http::jsonError(400, "folder not found");
            if (int e = tree.makeDir(*acct, *rel, name)) return tree::fail(e);
            int64_t id = db.createFolder(*userId, parentId, name);
            if (id < 0) return http::jsonError(500, "could not record folder (it is on disk; a rescan will index it)");
            auto f = db.getFolder(*userId, id);
            notifyUser(*userId, "files");
            return http::jsonSuccess(json{{"folder", f ? f->toJson() : json(nullptr)}}.dump());
        }
        // E2E: an encrypted folder name (opaque) means we store the plaintext blank.
        std::string encName = strField(body, "encName");
        std::string name;
        if (!encName.empty()) {
            if (!validEncName(encName)) return http::jsonError(400, "invalid enc name");
        } else {
            name = strField(body, "name");
            if (!validName(name)) return http::jsonError(400, "invalid folder name");
        }
        int64_t parentId = intField(body, "parentId", 0);

        if (!db.folderExists(*userId, parentId)) return http::jsonError(400, "folder not found");
        int64_t id = db.createFolder(*userId, parentId, name, encName);
        if (id < 0) return http::jsonError(400, "could not create folder");
        auto f = db.getFolder(*userId, id);
        notifyUser(*userId, "files");
        return http::jsonSuccess(json{{"folder", f ? f->toJson() : json(nullptr)}}.dump());
    });

    // ---- Rename / move folder ----
    CROW_ROUTE(app, "/api/folders/<int>").methods(crow::HTTPMethod::PATCH)
    ([&db, &tree](const crow::request& req, int folderId) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        json body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.is_object()) return http::jsonError(400, "invalid json");

        if (auto acct = tree::account(db, tree, *userId)) {
            if (body.contains("encName")) return tree::noEncryption();
            std::lock_guard<std::mutex> lk(storage::userLock(*userId));
            auto cur = db.getFolder(*userId, folderId);
            if (!cur) return http::jsonError(404, "not found");
            std::string newName = cur->name;
            if (body.contains("name")) {
                newName = strField(body, "name");
                if (!validName(newName) || !TreeStore::validUserName(newName)) return http::jsonError(400, "invalid folder name");
            }
            int64_t newParent = cur->parent_id;
            if (body.contains("parentId")) {
                newParent = intField(body, "parentId", 0);
                if (newParent == folderId || !db.folderExists(*userId, newParent)) return http::jsonError(400, "invalid move");
            }
            if (newName != cur->name || newParent != cur->parent_id) {
                auto from = tree::folderRel(db, *userId, cur->parent_id);
                auto to = tree::folderRel(db, *userId, newParent);
                if (!from || !to) return http::jsonError(400, "invalid move");
                // Moving a folder inside its own subtree: the target path runs through it.
                TreeStore::Rel self = *from; self.push_back(cur->name);
                if (to->size() >= self.size() && std::equal(self.begin(), self.end(), to->begin()))
                    return http::jsonError(400, "invalid move");
                if (int e = tree.rename(*acct, *from, cur->name, *to, newName)) return tree::fail(e);
                bool okDb = true;
                if (newName != cur->name) okDb = db.renameFolder(*userId, folderId, newName);
                if (okDb && newParent != cur->parent_id) okDb = db.moveFolder(*userId, folderId, newParent);
                if (!okDb) {
                    tree.rename(*acct, *to, newName, *from, cur->name);   // put the disk back
                    db.renameFolder(*userId, folderId, cur->name);
                    return http::jsonError(400, "invalid move");
                }
            }
            if (body.contains("starred") && body["starred"].is_boolean())
                db.setFolderStarred(*userId, folderId, body["starred"].get<bool>());
            auto f = db.getFolder(*userId, folderId);
            notifyUser(*userId, "files");
            return http::jsonSuccess(json{{"folder", f ? f->toJson() : json(nullptr)}}.dump());
        }

        if (!db.getFolder(*userId, folderId)) return http::jsonError(404, "not found");

        if (body.contains("encName")) {
            std::string encName = strField(body, "encName");
            if (!validEncName(encName)) return http::jsonError(400, "invalid enc name");
            db.renameFolder(*userId, folderId, "", encName);
        } else if (body.contains("name")) {
            std::string name = strField(body, "name");
            if (!validName(name)) return http::jsonError(400, "invalid folder name");
            db.renameFolder(*userId, folderId, name);
        }
        if (body.contains("parentId")) {
            int64_t parentId = intField(body, "parentId", 0);
            if (!db.moveFolder(*userId, folderId, parentId))
                return http::jsonError(400, "invalid move");
        }
        if (body.contains("starred") && body["starred"].is_boolean())
            db.setFolderStarred(*userId, folderId, body["starred"].get<bool>());
        auto f = db.getFolder(*userId, folderId);
        notifyUser(*userId, "files");
        return http::jsonSuccess(json{{"folder", f ? f->toJson() : json(nullptr)}}.dump());
    });

    // ---- Delete folder (recursive) ----
    CROW_ROUTE(app, "/api/folders/<int>").methods(crow::HTTPMethod::DELETE)
    ([&db, &store, &tree](const crow::request& req, int folderId) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        if (auto acct = tree::account(db, tree, *userId)) {
            std::lock_guard<std::mutex> lk(storage::userLock(*userId));
            auto cur = db.getFolder(*userId, folderId);
            if (!cur) return http::jsonError(404, "not found");
            auto rel = tree::folderRel(db, *userId, cur->parent_id);
            if (!rel) return http::jsonError(409, "folder chain is broken; rescan first");
            // The whole folder goes into .trash in one rename (or is removed when TRASH_DAYS=0).
            if (int e = tree.trash(*acct, *rel, cur->name); e && e != ENOENT) return tree::fail(e);
            std::vector<std::string> ignored;
            if (!db.deleteFolderRecursive(*userId, folderId, ignored))
                return http::jsonError(500, "removed on disk but the index update failed; a rescan will fix it");
            notifyUser(*userId, "files");
            return http::jsonSuccess(R"({"ok":true})");
        }

        if (!db.getFolder(*userId, folderId)) return http::jsonError(404, "not found");

        std::vector<std::string> storageKeys;
        if (!db.deleteFolderRecursive(*userId, folderId, storageKeys))
            return http::jsonError(500, "delete failed");
        for (const auto& key : storageKeys) store.remove(*userId, key); // free the bytes
        notifyUser(*userId, "files");
        return http::jsonSuccess(R"({"ok":true})");
    });

    // ---- Storage usage ----
    CROW_ROUTE(app, "/api/usage").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        auto [bytes, count] = db.usage(*userId);
        auto u = db.findUserById(*userId);
        json quota = (u && u->storage_quota_bytes) ? json(*u->storage_quota_bytes) : json(nullptr);   // null = unlimited
        return http::jsonSuccess(json{{"used", bytes}, {"files", count}, {"quota", quota}}.dump());
    });

    // ---- Search / category listing (across all folders) ----
    CROW_ROUTE(app, "/api/search").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        std::string q, category;
        if (const char* p = req.url_params.get("q")) q = p;
        if (const char* p = req.url_params.get("category")) category = p;
        if (q.size() > 200) q = q.substr(0, 200);

        json files = json::array();
        for (const auto& f : db.searchFiles(*userId, q, category, 500)) files.push_back(f.toJson());
        json folders = json::array();
        for (const auto& f : db.searchFolders(*userId, q, 200)) folders.push_back(f.toJson());
        return http::jsonSuccess(json{{"files", files}, {"folders", folders}}.dump());
    });

    // ---- Starred ----
    CROW_ROUTE(app, "/api/starred").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        json folders = json::array();
        for (const auto& f : db.starredFolders(*userId)) folders.push_back(f.toJson());
        json files = json::array();
        for (const auto& f : db.starredFiles(*userId)) files.push_back(f.toJson());
        return http::jsonSuccess(json{{"folders", folders}, {"files", files}}.dump());
    });

    // ---- Recent (recently added files) ----
    CROW_ROUTE(app, "/api/recent").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        json files = json::array();
        for (const auto& f : db.recentFiles(*userId, 50)) files.push_back(f.toJson());
        return http::jsonSuccess(json{{"files", files}}.dump());
    });

    // ---- Rename / move file ----
    CROW_ROUTE(app, "/api/files/<int>").methods(crow::HTTPMethod::PATCH)
    ([&db, &tree](const crow::request& req, int fileId) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        json body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.is_object()) return http::jsonError(400, "invalid json");

        if (auto acct = tree::account(db, tree, *userId)) {
            if (body.contains("encName")) return tree::noEncryption();
            std::lock_guard<std::mutex> lk(storage::userLock(*userId));
            auto cur = db.getFile(*userId, fileId);
            if (!cur) return http::jsonError(404, "not found");
            std::string newName = cur->name;
            if (body.contains("name")) {
                newName = strField(body, "name");
                if (!validName(newName) || !TreeStore::validUserName(newName)) return http::jsonError(400, "invalid filename");
            }
            int64_t newFolder = cur->folder_id;
            if (body.contains("folderId")) {
                newFolder = intField(body, "folderId", 0);
                if (!db.folderExists(*userId, newFolder)) return http::jsonError(400, "folder not found");
            }
            if (newName != cur->name || newFolder != cur->folder_id) {
                auto from = tree::folderRel(db, *userId, cur->folder_id);
                auto to = tree::folderRel(db, *userId, newFolder);
                if (!from || !to) return http::jsonError(400, "folder not found");
                if (int e = tree.rename(*acct, *from, cur->name, *to, newName)) return tree::fail(e);
                bool okDb = true;
                if (newName != cur->name) okDb = db.renameFile(*userId, fileId, newName);
                if (okDb && newFolder != cur->folder_id) okDb = db.moveFile(*userId, fileId, newFolder);
                if (!okDb) {
                    tree.rename(*acct, *to, newName, *from, cur->name);
                    db.renameFile(*userId, fileId, cur->name);
                    return http::jsonError(500, "could not update the index");
                }
            }
            if (body.contains("starred") && body["starred"].is_boolean())
                db.setFileStarred(*userId, fileId, body["starred"].get<bool>());
            auto f = db.getFile(*userId, fileId);
            notifyUser(*userId, "files");
            return http::jsonSuccess(json{{"file", f ? f->toJson() : json(nullptr)}}.dump());
        }

        if (!db.getFile(*userId, fileId)) return http::jsonError(404, "not found");

        if (body.contains("encName")) {
            std::string encName = strField(body, "encName");
            if (!validEncName(encName)) return http::jsonError(400, "invalid enc name");
            db.renameFile(*userId, fileId, "", encName);
        } else if (body.contains("name")) {
            std::string name = strField(body, "name");
            if (!validName(name)) return http::jsonError(400, "invalid filename");
            db.renameFile(*userId, fileId, name);
        }
        if (body.contains("folderId")) {
            int64_t folderId = intField(body, "folderId", 0);
            if (!db.folderExists(*userId, folderId)) return http::jsonError(400, "folder not found");
            db.moveFile(*userId, fileId, folderId);
        }
        if (body.contains("starred") && body["starred"].is_boolean())
            db.setFileStarred(*userId, fileId, body["starred"].get<bool>());
        auto f = db.getFile(*userId, fileId);
        notifyUser(*userId, "files");
        return http::jsonSuccess(json{{"file", f ? f->toJson() : json(nullptr)}}.dump());
    });
}

} // namespace routes
