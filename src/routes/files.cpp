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

// Reject any control char, including \t \r \n — defense-in-depth against header
// injection / odd whitespace in stored names.
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
// Percent-decode an X-Filename header value so we store the human-readable
// name (the client encodes it to keep the header ASCII-safe). '+' is left as-is
// (encodeURIComponent uses %20 for space, not '+').
std::string urlDecode(const std::string& s) {
    auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '%' && i + 2 < s.size()) {
            int hi = hex(s[i + 1]), lo = hex(s[i + 2]);
            if (hi >= 0 && lo >= 0) { out += static_cast<char>(hi * 16 + lo); i += 2; continue; }
        }
        out += s[i];
    }
    return out;
}

bool isValidDisplayName(const std::string& name) {
    if (name.empty() || name.size() > 255) return false;
    if (hasAnyControlChar(name)) return false;
    if (name.find('/') != std::string::npos) return false;
    if (name.find('\\') != std::string::npos) return false;
    if (name == "." || name == ".." ) return false;
    return true;
}

// An encrypted name is an opaque "iv.ct" base64 blob (E2E). We can't read it,
// but we bound its size and keep it to the base64 alphabet so nothing odd is
// stored or echoed back into a JSON/HTTP context.
bool isValidEncName(const std::string& s) {
    if (s.empty() || s.size() > 4096) return false;
    for (unsigned char c : s) {
        bool okChar = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '.';
        if (!okChar) return false;
    }
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

        // E2E: the filename may be encrypted (X-Enc-Name). When present we store
        // the plaintext name blank and keep only the opaque blob; otherwise the
        // legacy plaintext X-Filename path (still used by non-E2E clients/tests).
        std::string encName = req.get_header_value("X-Enc-Name");
        std::string name;
        if (!encName.empty()) {
            if (!isValidEncName(encName)) return http::jsonError(400, "invalid enc name");
        } else {
            name = urlDecode(req.get_header_value("X-Filename"));
            if (name.empty()) return http::jsonError(400, "missing X-Filename header");
            if (!isValidDisplayName(name)) return http::jsonError(400, "invalid filename");
        }
        // Empty (0-byte) files are allowed — a cloud legitimately stores them.

        int64_t folderId = 0; // 0 = root
        std::string folderHdr = req.get_header_value("X-Folder");
        if (!folderHdr.empty()) { try { folderId = std::stoll(folderHdr); } catch (...) { folderId = 0; } }
        if (!db.folderExists(*userId, folderId)) return http::jsonError(400, "folder not found");

        std::string mime = req.get_header_value("Content-Type");
        if (mime.empty() || mime.size() > 255 || hasAnyControlChar(mime))
            mime = "application/octet-stream";

        // E2E: the body may be ciphertext with a wrapped per-file key; the client
        // reports the plaintext size for display. Opaque to us either way.
        std::string wrappedKey = req.get_header_value("X-Wrapped-Key");
        int64_t size = static_cast<int64_t>(req.body.size());
        std::string plainSize = req.get_header_value("X-Plain-Size");
        if (!plainSize.empty()) { try { size = std::stoll(plainSize); } catch (...) {} }

        // Opaque on-disk name — decouples storage from the user-facing filename.
        std::string storageKey = security::Crypto::randomHex(16);
        if (!store.write(*userId, storageKey, req.body.data(), req.body.size())) {
            return http::jsonError(500, "storage write failed");
        }

        int64_t id = db.addFile(*userId, folderId, name, mime, size, storageKey, wrappedKey, encName);
        if (id < 0) {
            store.remove(*userId, storageKey);  // don't leak an orphan blob
            return http::jsonError(500, "could not record file");
        }

        json out = {{"id", id}, {"name", name}, {"mime", mime}, {"size", size},
                    {"folderId", folderId}, {"encName", encName}};
        return http::jsonSuccess(out.dump());
    });

    // ---- List ----
    CROW_ROUTE(app, "/api/files").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        // Root-folder files. The full tree is browsed via GET /api/fs.
        json files = json::array();
        for (const auto& f : db.listFiles(*userId, 0)) files.push_back(f.toJson());
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
