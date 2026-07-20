#include "routes/fs.h"
#include "security/request_auth.h"

#include <nlohmann/json.hpp>
#include <string>

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

std::string strField(const json& j, const char* key) {
    if (j.contains(key) && j[key].is_string()) return j[key].get<std::string>();
    return "";
}

int64_t intField(const json& j, const char* key, int64_t def) {
    if (j.contains(key) && j[key].is_number_integer()) return j[key].get<int64_t>();
    return def;
}

} // namespace

void registerFsRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db, FileStore& store) {

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
    ([&db](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        json body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.is_object()) return http::jsonError(400, "invalid json");
        std::string name = strField(body, "name");
        if (!validName(name)) return http::jsonError(400, "invalid folder name");
        int64_t parentId = intField(body, "parentId", 0);

        int64_t id = db.createFolder(*userId, parentId, name);
        if (id < 0) return http::jsonError(400, "could not create folder");
        auto f = db.getFolder(*userId, id);
        return http::jsonSuccess(json{{"folder", f ? f->toJson() : json(nullptr)}}.dump());
    });

    // ---- Rename / move folder ----
    CROW_ROUTE(app, "/api/folders/<int>").methods(crow::HTTPMethod::PATCH)
    ([&db](const crow::request& req, int folderId) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        json body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.is_object()) return http::jsonError(400, "invalid json");
        if (!db.getFolder(*userId, folderId)) return http::jsonError(404, "not found");

        if (body.contains("name")) {
            std::string name = strField(body, "name");
            if (!validName(name)) return http::jsonError(400, "invalid folder name");
            db.renameFolder(*userId, folderId, name);
        }
        if (body.contains("parentId")) {
            int64_t parentId = intField(body, "parentId", 0);
            if (!db.moveFolder(*userId, folderId, parentId))
                return http::jsonError(400, "invalid move");
        }
        auto f = db.getFolder(*userId, folderId);
        return http::jsonSuccess(json{{"folder", f ? f->toJson() : json(nullptr)}}.dump());
    });

    // ---- Delete folder (recursive) ----
    CROW_ROUTE(app, "/api/folders/<int>").methods(crow::HTTPMethod::DELETE)
    ([&db, &store](const crow::request& req, int folderId) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        if (!db.getFolder(*userId, folderId)) return http::jsonError(404, "not found");

        std::vector<std::string> storageKeys;
        if (!db.deleteFolderRecursive(*userId, folderId, storageKeys))
            return http::jsonError(500, "delete failed");
        for (const auto& key : storageKeys) store.remove(*userId, key); // free the bytes
        return http::jsonSuccess(R"({"ok":true})");
    });

    // ---- Rename / move file ----
    CROW_ROUTE(app, "/api/files/<int>").methods(crow::HTTPMethod::PATCH)
    ([&db](const crow::request& req, int fileId) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        json body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.is_object()) return http::jsonError(400, "invalid json");
        if (!db.getFile(*userId, fileId)) return http::jsonError(404, "not found");

        if (body.contains("name")) {
            std::string name = strField(body, "name");
            if (!validName(name)) return http::jsonError(400, "invalid filename");
            db.renameFile(*userId, fileId, name);
        }
        if (body.contains("folderId")) {
            int64_t folderId = intField(body, "folderId", 0);
            if (!db.folderExists(*userId, folderId)) return http::jsonError(400, "folder not found");
            db.moveFile(*userId, fileId, folderId);
        }
        auto f = db.getFile(*userId, fileId);
        return http::jsonSuccess(json{{"file", f ? f->toJson() : json(nullptr)}}.dump());
    });
}

} // namespace routes
