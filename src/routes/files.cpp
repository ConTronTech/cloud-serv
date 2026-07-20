#include "routes/files.h"
#include "security/request_auth.h"
#include "security/crypto.h"
#include "security/sanitizer.h"
#include "utils/logger.h"

#include <nlohmann/json.hpp>
#include <fstream>
#include <algorithm>
#include <cstdint>

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

// Cap on bytes served per Range response — bounds memory for a single request
// while the client keeps requesting further ranges as it plays/seeks.
const int64_t RANGE_CHUNK_CAP = 8 * 1024 * 1024;

// Parse a "bytes=start-end" Range header against a known total size.
// Returns false if unparseable or unsatisfiable (caller should 416).
bool parseRange(const std::string& header, int64_t total, int64_t& start, int64_t& end) {
    const std::string prefix = "bytes=";
    if (header.compare(0, prefix.size(), prefix) != 0) return false;
    std::string spec = header.substr(prefix.size());
    auto dash = spec.find('-');
    if (dash == std::string::npos) return false;
    std::string s = spec.substr(0, dash);
    std::string e = spec.substr(dash + 1);

    try {
        if (s.empty()) {
            // Suffix range: last N bytes ("bytes=-N").
            if (e.empty()) return false;
            int64_t n = std::stoll(e);
            if (n <= 0) return false;
            start = std::max<int64_t>(0, total - n);
            end = total - 1;
        } else {
            start = std::stoll(s);
            end = e.empty() ? total - 1 : std::stoll(e);
        }
    } catch (...) {
        return false;
    }
    if (start < 0 || start >= total || end < start) return false;
    if (end >= total) end = total - 1;
    return true;
}

// Read [start, end] (inclusive) from a file into a string.
std::string readSlice(const std::string& path, int64_t start, int64_t len) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    f.seekg(start);
    std::string buf(static_cast<size_t>(len), '\0');
    f.read(&buf[0], len);
    buf.resize(static_cast<size_t>(f.gcount()));
    return buf;
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
        // Empty (0-byte) files are allowed — a cloud legitimately stores them.

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

    // ---- Content (inline, Range-capable) — for playback / preview ----
    // <video>/<audio>/<img> point their src here; auth comes from the session
    // cookie (they can't send Authorization). Supports HTTP Range for seeking.
    CROW_ROUTE(app, "/api/files/<int>/content").methods(crow::HTTPMethod::GET)
    ([&db, &store](const crow::request& req, int fileId) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        auto meta = db.getFile(*userId, fileId);
        if (!meta) return http::jsonError(404, "not found");

        const std::string path = store.pathFor(*userId, meta->storage_key);
        const int64_t size = meta->size;

        std::string rangeHeader = req.get_header_value("Range");
        if (rangeHeader.empty()) {
            // No range: stream the whole file from disk (low memory), inline.
            crow::response res;
            res.set_static_file_info_unsafe(path, meta->mime);
            if (res.code == 404) return http::jsonError(404, "not found");
            res.add_header("Accept-Ranges", "bytes");
            res.add_header("Content-Disposition", "inline");
            return res;
        }

        int64_t start = 0, end = size - 1;
        if (size <= 0 || !parseRange(rangeHeader, size, start, end)) {
            crow::response res(416); // Range Not Satisfiable
            res.add_header("Content-Range", "bytes */" + std::to_string(size));
            return res;
        }

        // Serve at most RANGE_CHUNK_CAP bytes this response; the client asks for more.
        if (end - start + 1 > RANGE_CHUNK_CAP) end = start + RANGE_CHUNK_CAP - 1;
        const int64_t len = end - start + 1;

        std::string slice = readSlice(path, start, len);
        crow::response res(206);
        res.body = std::move(slice);
        res.add_header("Content-Type", meta->mime);
        res.add_header("Accept-Ranges", "bytes");
        res.add_header("Content-Range",
                       "bytes " + std::to_string(start) + "-" + std::to_string(end) +
                       "/" + std::to_string(size));
        res.add_header("Content-Disposition", "inline");
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
