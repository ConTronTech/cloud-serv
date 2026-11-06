#include "routes/files.h"
#include "security/request_auth.h"
#include "security/crypto.h"
#include "security/sanitizer.h"
#include "utils/logger.h"
#include "routes/events.h"
#include "storage/user_lock.h"
#include "routes/tree_helpers.h"
#include <mutex>

#include <nlohmann/json.hpp>
#include <fstream>
#include <algorithm>
#include <cstdint>
#include <cctype>

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

// Only these types are ever shown inline from /content. Anything else (HTML, SVG,
// JS, XML, unknown...) is sent as an opaque download, so an uploaded web page can
// never run as this site. Encrypted blobs are ciphertext anyway (octet-stream).
std::string lowerMime(std::string m) {
    auto semi = m.find(';'); if (semi != std::string::npos) m.resize(semi);
    for (auto& ch : m) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    while (!m.empty() && m.back() == ' ') m.pop_back();
    return m;
}
bool inlineSafe(const std::string& rawMime) {
    const std::string m = lowerMime(rawMime);
    if (m.rfind("video/", 0) == 0 || m.rfind("audio/", 0) == 0) return true;
    static const char* ok[] = {"image/png", "image/jpeg", "image/gif", "image/webp", "image/avif",
                               "image/bmp", "application/pdf", "text/plain"};
    for (auto* o : ok) if (m == o) return true;
    return false;
}
// Headers for anything served from a user's storage.
void contentHeaders(crow::response& res, const std::string& mime) {
    const bool safe = inlineSafe(mime);
    res.set_header("Content-Type", safe ? (lowerMime(mime) == "text/plain" ? "text/plain; charset=utf-8" : lowerMime(mime))
                                        : "application/octet-stream");
    res.set_header("Content-Disposition", safe ? "inline" : "attachment");
    res.set_header("X-Content-Type-Options", "nosniff");
    // Even if a browser did render it, it gets no scripts, no forms, no same-origin powers.
    res.add_header("Content-Security-Policy", "sandbox; default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'");
}

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
                        CloudDB& db, FileStore& store, TreeStore& tree) {

    // ---- Upload (raw body) ----
    // The web/mobile client sends the file bytes as the request body with an
    // X-Filename header. Simple and streamable-friendly; no multipart parsing.
    CROW_ROUTE(app, "/api/files").methods(crow::HTTPMethod::POST)
    ([&db, &store, &tree](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        // Real-folder account: bytes go straight into the folder tree under their own name.
        if (auto acct = tree::account(db, tree, *userId)) {
            if (!req.get_header_value("X-Enc-Name").empty() || !req.get_header_value("X-Enc-Mime").empty() ||
                !req.get_header_value("X-Wrapped-Key").empty()) return tree::noEncryption();
            std::string name = urlDecode(req.get_header_value("X-Filename"));
            if (name.empty()) return http::jsonError(400, "missing X-Filename header");
            if (!isValidDisplayName(name) || !TreeStore::validUserName(name)) return http::jsonError(400, "invalid filename");
            int64_t folderId = 0;
            std::string folderHdr = req.get_header_value("X-Folder");
            if (!folderHdr.empty()) { try { folderId = std::stoll(folderHdr); } catch (...) { folderId = 0; } }
            std::string mime = req.get_header_value("Content-Type");
            if (mime.empty() || mime.size() > 255 || hasAnyControlChar(mime)) mime = TreeStore::mimeFor(name);

            std::lock_guard<std::mutex> userLk(storage::userLock(*userId));
            if (!db.folderExists(*userId, folderId)) return http::jsonError(400, "folder not found");
            auto rel = tree::folderRel(db, *userId, folderId);
            if (!rel) return http::jsonError(400, "folder not found");
            const int64_t size = static_cast<int64_t>(req.body.size());
            if (!db.hasQuotaRoom(*userId, size)) return http::jsonError(413, "storage quota exceeded");
            std::string finalName;
            if (int e = tree.writeFile(*acct, *rel, name, req.body.data(), req.body.size(), true, finalName))
                return tree::fail(e);
            int64_t id = db.addFile(*userId, folderId, finalName, mime, size, "-", "", "", "", size);
            if (id < 0) return http::jsonError(500, "could not record file (it is on disk; a rescan will index it)");
            notifyUser(*userId, "files");
            return http::jsonSuccess(json{{"id", id}, {"name", finalName}, {"mime", mime}, {"size", size},
                                          {"folderId", folderId}, {"encName", ""}, {"encMime", ""}}.dump());
        }

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

        // E2E: the mime may be encrypted (X-Enc-Mime); then we store a generic
        // placeholder and keep only the opaque blob. Otherwise the Content-Type.
        std::string encMime = req.get_header_value("X-Enc-Mime");
        std::string mime;
        if (!encMime.empty()) {
            if (!isValidEncName(encMime)) return http::jsonError(400, "invalid enc mime");
            mime = "application/octet-stream";
        } else {
            mime = req.get_header_value("Content-Type");
            if (mime.empty() || mime.size() > 255 || hasAnyControlChar(mime))
                mime = "application/octet-stream";
        }

        // E2E: the body may be ciphertext with a wrapped per-file key; the client
        // reports the plaintext size for display. Opaque to us either way.
        std::string wrappedKey = req.get_header_value("X-Wrapped-Key");
        const int64_t stored = static_cast<int64_t>(req.body.size());
        int64_t size = stored;   // display only; never more than what was sent
        std::string plainSize = req.get_header_value("X-Plain-Size");
        if (!plainSize.empty()) {
            try { int64_t p = std::stoll(plainSize); if (p >= 0 && p <= stored) size = p; } catch (...) {}
        }

        std::lock_guard<std::mutex> userLk(storage::userLock(*userId));
        if (!db.hasQuotaRoom(*userId, static_cast<int64_t>(req.body.size())))
            return http::jsonError(413, "storage quota exceeded");

        // Opaque on-disk name — decouples storage from the user-facing filename.
        std::string storageKey = security::Crypto::randomHex(16);
        if (!store.write(*userId, storageKey, req.body.data(), req.body.size())) {
            return http::jsonError(500, "storage write failed");
        }

        int64_t id = db.addFile(*userId, folderId, name, mime, size, storageKey, wrappedKey, encName, encMime, stored);
        if (id < 0) {
            store.remove(*userId, storageKey);  // don't leak an orphan blob
            return http::jsonError(500, "could not record file");
        }

        json out = {{"id", id}, {"name", name}, {"mime", mime}, {"size", size},
                    {"folderId", folderId}, {"encName", encName}, {"encMime", encMime}};
        notifyUser(*userId, "files");
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
    ([&db, &store, &tree](const crow::request& req, int fileId) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        auto meta = db.getFile(*userId, fileId);
        if (!meta) return http::jsonError(404, "not found");

        std::string path;
        if (auto acct = tree::account(db, tree, *userId)) {
            // Walked component by component with O_NOFOLLOW; empty if anything is off.
            auto rel = tree::folderRel(db, *userId, meta->folder_id);
            if (rel) path = tree.servePath(*acct, *rel, meta->name);
            if (path.empty()) return http::jsonError(404, "not found");
        } else {
            path = store.pathFor(*userId, meta->storage_key);
        }
        crow::response res;
        // Path is internal (opaque key, or a tree path verified above), so the "unsafe" variant is fine.
        res.set_static_file_info_unsafe(path, meta->mime);
        if (res.code == 404) return http::jsonError(404, "not found");

        std::string safeName = security::Sanitizer::safeDispositionName(meta->name);
        res.set_header("Content-Disposition", "attachment; filename=\"" + safeName + "\"");
        res.set_header("X-Content-Type-Options", "nosniff");
        if (!inlineSafe(meta->mime)) res.set_header("Content-Type", "application/octet-stream");
        return res;
    });

    // ---- Content (inline, Range-capable) — for playback / preview ----
    // <video>/<audio>/<img> point their src here; auth comes from the session
    // cookie (they can't send Authorization). Supports HTTP Range for seeking.
    CROW_ROUTE(app, "/api/files/<int>/content").methods(crow::HTTPMethod::GET)
    ([&db, &store, &tree](const crow::request& req, int fileId) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        auto meta = db.getFile(*userId, fileId);
        if (!meta) return http::jsonError(404, "not found");

        std::string path;
        int64_t size = meta->size;
        if (auto acct = tree::account(db, tree, *userId)) {
            // Real size from disk: the file may have changed since the last scan.
            auto rel = tree::folderRel(db, *userId, meta->folder_id);
            if (rel) path = tree.servePath(*acct, *rel, meta->name, &size);
            if (path.empty()) return http::jsonError(404, "not found");
        } else {
            path = store.pathFor(*userId, meta->storage_key);
        }

        std::string rangeHeader = req.get_header_value("Range");
        if (rangeHeader.empty()) {
            // No range: stream the whole file from disk (low memory), inline.
            crow::response res;
            res.set_static_file_info_unsafe(path, meta->mime);
            if (res.code == 404) return http::jsonError(404, "not found");
            res.add_header("Accept-Ranges", "bytes");
            contentHeaders(res, meta->mime);
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
        res.add_header("Accept-Ranges", "bytes");
        res.add_header("Content-Range",
                       "bytes " + std::to_string(start) + "-" + std::to_string(end) +
                       "/" + std::to_string(size));
        contentHeaders(res, meta->mime);
        return res;
    });

    // ---- Delete ----
    CROW_ROUTE(app, "/api/files/<int>").methods(crow::HTTPMethod::DELETE)
    ([&db, &store, &tree](const crow::request& req, int fileId) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        if (auto acct = tree::account(db, tree, *userId)) {
            std::lock_guard<std::mutex> userLk(storage::userLock(*userId));
            auto meta = db.getFile(*userId, fileId);
            if (!meta) return http::jsonError(404, "not found");
            auto rel = tree::folderRel(db, *userId, meta->folder_id);
            if (!rel) return http::jsonError(409, "folder chain is broken; rescan first");
            // Into .trash (or gone, if TRASH_DAYS=0). Already missing on disk = just drop the row.
            if (int e = tree.trash(*acct, *rel, meta->name); e && e != ENOENT) return tree::fail(e);
            db.deleteFile(*userId, fileId);
            notifyUser(*userId, "files");
            return http::jsonSuccess(R"({"ok":true})");
        }

        auto meta = db.getFile(*userId, fileId);
        if (!meta) return http::jsonError(404, "not found");

        db.deleteFile(*userId, fileId);
        store.remove(*userId, meta->storage_key);
        notifyUser(*userId, "files");
        return http::jsonSuccess(R"({"ok":true})");
    });
}

} // namespace routes
