#include "routes/files.h"
#include "security/request_auth.h"
#include "security/crypto.h"
#include "security/sanitizer.h"
#include "utils/logger.h"

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace routes {

namespace {

// Reject any control char, including \t \r \n (Sanitizer::containsControlChars
// intentionally permits those, so we check explicitly here — defense-in-depth
// against header injection / odd whitespace in stored names).
bool hasAnyControlChar(const std::string& s) {
    for (unsigned char c : s) {
        if (c < 0x20 || c == 0x7f) return true;
    }
    return false;
}

// A display filename is stored as metadata only — never used as a disk path
// (blobs use an opaque storage key). We still reject anything unsafe to render
// or put in a header. Note: HTML metacharacters (< > " ' &) are allowed here
// because a filename can legitimately contain them; clients MUST escape the
// name when rendering it as HTML.
bool isValidDisplayName(const std::string& name) {
    if (name.empty() || name.size() > 255) return false;
    if (hasAnyControlChar(name)) return false;
    if (name.find('/') != std::string::npos) return false;
    if (name.find('\\') != std::string::npos) return false;
    if (name == "." || name == ".." ) return false;
    return true;
}

} // namespace

void registerFileRoutes(crow::App<http::SecurityMiddleware>& app,
                        CloudDB& db, FileStore& store) {

    // ---- Upload (raw body) ----
    // The web/mobile client sends the file bytes as the request body with an
    // X-Filename header. Simple and streamable-friendly; no multipart parsing.
    CROW_ROUTE(app, "/api/files").methods(crow::HTTPMethod::POST)
    ([&db, &store](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        std::string name = req.get_header_value("X-Filename");
        if (name.empty()) return http::jsonError(400, "missing X-Filename header");
        if (!isValidDisplayName(name)) return http::jsonError(400, "invalid filename");
        if (req.body.empty()) return http::jsonError(400, "empty body");

        std::string mime = req.get_header_value("Content-Type");
        if (mime.empty() || mime.size() > 255 || hasAnyControlChar(mime))
            mime = "application/octet-stream";

        // Opaque on-disk name — decouples storage from the user-facing filename.
        std::string storageKey = security::Crypto::randomHex(16);
        if (!store.write(*userId, storageKey, req.body.data(), req.body.size())) {
            return http::jsonError(500, "storage write failed");
        }

        int64_t size = static_cast<int64_t>(req.body.size());
        int64_t id = db.addFile(*userId, name, mime, size, storageKey);
        if (id < 0) {
            store.remove(*userId, storageKey);  // don't leak an orphan blob
            return http::jsonError(500, "could not record file");
        }

        json out = {{"id", id}, {"name", name}, {"mime", mime}, {"size", size}};
        return http::jsonSuccess(out.dump());
    });

    // ---- List ----
    CROW_ROUTE(app, "/api/files").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        json files = json::array();
        for (const auto& f : db.listFiles(*userId)) files.push_back(f.toJson());
        return http::jsonSuccess(json{{"files", files}}.dump());
    });

    // ---- Download (streamed from disk) ----
    CROW_ROUTE(app, "/api/files/<int>").methods(crow::HTTPMethod::GET)
    ([&db, &store](const crow::request& req, int fileId) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        auto meta = db.getFile(*userId, fileId);
        if (!meta) return http::jsonError(404, "not found");

        crow::response res;
        // Path is internal + opaque, so the "unsafe" (no re-sanitize) variant is fine.
        res.set_static_file_info_unsafe(store.pathFor(*userId, meta->storage_key), meta->mime);
        if (res.code == 404) return http::jsonError(404, "not found");

        std::string safeName = security::Sanitizer::safeDispositionName(meta->name);
        res.add_header("Content-Disposition", "attachment; filename=\"" + safeName + "\"");
        return res;
    });

    // ---- Delete ----
    CROW_ROUTE(app, "/api/files/<int>").methods(crow::HTTPMethod::DELETE)
    ([&db, &store](const crow::request& req, int fileId) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        auto meta = db.getFile(*userId, fileId);
        if (!meta) return http::jsonError(404, "not found");

        db.deleteFile(*userId, fileId);
        store.remove(*userId, meta->storage_key);
        return http::jsonSuccess(R"({"ok":true})");
    });
}

} // namespace routes
