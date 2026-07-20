#include "routes/uploads.h"
#include "security/request_auth.h"
#include "security/crypto.h"

#include <nlohmann/json.hpp>
#include <string>

using json = nlohmann::json;

namespace routes {

namespace {

bool anyControlChar(const std::string& s) {
    for (unsigned char c : s) if (c < 0x20 || c == 0x7f) return true;
    return false;
}

// Same rules as the direct-upload path: display name only, never a disk path.
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

void registerUploadRoutes(crow::App<http::SecurityMiddleware>& app,
                          CloudDB& db, FileStore& store, int64_t maxFileBytes) {

    // ---- Init: create an upload session + empty blob ----
    CROW_ROUTE(app, "/api/uploads/init").methods(crow::HTTPMethod::POST)
    ([&db, &store, maxFileBytes](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        json body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.is_object()) return http::jsonError(400, "invalid json");

        std::string name = strField(body, "name");
        if (!validName(name)) return http::jsonError(400, "invalid filename");

        std::string mime = strField(body, "mime");
        if (mime.empty() || mime.size() > 255 || anyControlChar(mime))
            mime = "application/octet-stream";

        int64_t size = intField(body, "size", 0);
        if (size < 0) size = 0;
        if (size > maxFileBytes) return http::jsonError(413, "file too large");

        int64_t folderId = intField(body, "folderId", 0);
        if (!db.folderExists(*userId, folderId)) return http::jsonError(400, "folder not found");

        std::string uploadId = security::Crypto::randomHex(16);
        std::string storageKey = security::Crypto::randomHex(16);
        if (!store.write(*userId, storageKey, nullptr, 0))  // create empty blob
            return http::jsonError(500, "storage init failed");
        if (!db.createUploadSession(*userId, uploadId, folderId, name, mime, size, storageKey)) {
            store.remove(*userId, storageKey);
            return http::jsonError(500, "could not create upload");
        }
        return http::jsonSuccess(json{{"uploadId", uploadId}, {"received", 0}}.dump());
    });

    // ---- Status / resume ----
    CROW_ROUTE(app, "/api/uploads/<string>").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req, const std::string& id) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        auto s = db.getUploadSession(*userId, id);
        if (!s) return http::jsonError(404, "not found");
        return http::jsonSuccess(
            json{{"received", s->received}, {"size", s->size}, {"name", s->name}}.dump());
    });

    // ---- Append a chunk (raw body, X-Offset header) ----
    CROW_ROUTE(app, "/api/uploads/<string>").methods(crow::HTTPMethod::PUT)
    ([&db, &store, maxFileBytes](const crow::request& req, const std::string& id) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        auto s = db.getUploadSession(*userId, id);
        if (!s) return http::jsonError(404, "not found");

        // Client must send chunks in order; X-Offset must match what we have.
        std::string offStr = req.get_header_value("X-Offset");
        int64_t offset = 0;
        try { offset = std::stoll(offStr); } catch (...) { return http::jsonError(400, "bad offset"); }
        if (offset != s->received) {
            // Tell the client where we actually are so it can resync.
            auto res = http::jsonError(409, "offset mismatch");
            res.set_header("Content-Type", "application/json");
            res.body = json{{"error", "offset_mismatch"}, {"received", s->received}}.dump();
            return res;
        }

        int64_t newReceived = s->received + static_cast<int64_t>(req.body.size());
        if (newReceived > maxFileBytes) return http::jsonError(413, "file too large");
        if (s->size > 0 && newReceived > s->size) return http::jsonError(400, "exceeds declared size");

        if (!store.append(*userId, s->storage_key, req.body.data(), req.body.size()))
            return http::jsonError(500, "storage write failed");
        db.setUploadReceived(*userId, id, newReceived);

        return http::jsonSuccess(json{{"received", newReceived}}.dump());
    });

    // ---- Complete: turn the blob into a real file ----
    CROW_ROUTE(app, "/api/uploads/<string>/complete").methods(crow::HTTPMethod::POST)
    ([&db, &store](const crow::request& req, const std::string& id) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        auto s = db.getUploadSession(*userId, id);
        if (!s) return http::jsonError(404, "not found");

        // Sanity: on-disk size should match what we recorded.
        int64_t onDisk = store.sizeOf(*userId, s->storage_key);
        if (onDisk != s->received) return http::jsonError(409, "size mismatch");
        if (s->size > 0 && s->received != s->size) return http::jsonError(400, "incomplete upload");

        int64_t fileId = db.addFile(*userId, s->folder_id, s->name, s->mime, s->received, s->storage_key);
        if (fileId < 0) return http::jsonError(500, "could not finalize");
        db.deleteUploadSession(*userId, id); // keep the blob; it's now a real file

        json out = {{"id", fileId}, {"name", s->name}, {"mime", s->mime}, {"size", s->received}};
        return http::jsonSuccess(json{{"file", out}}.dump());
    });

    // ---- Abort: discard the partial blob + session ----
    CROW_ROUTE(app, "/api/uploads/<string>").methods(crow::HTTPMethod::DELETE)
    ([&db, &store](const crow::request& req, const std::string& id) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        auto s = db.getUploadSession(*userId, id);
        if (!s) return http::jsonError(404, "not found");
        store.remove(*userId, s->storage_key);
        db.deleteUploadSession(*userId, id);
        return http::jsonSuccess(R"({"ok":true})");
    });
}

} // namespace routes
