#include "routes/uploads.h"
#include "security/request_auth.h"
#include "security/crypto.h"

#include <nlohmann/json.hpp>
#include <string>

#include "routes/events.h"
#include "storage/user_lock.h"
#include "routes/tree_helpers.h"
#include <mutex>
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

void registerUploadRoutes(crow::App<http::SecurityMiddleware>& app,
                          CloudDB& db, FileStore& store, TreeStore& tree, int64_t maxFileBytes) {

    // Drop the partial bytes of an upload, wherever this account keeps them.
    auto dropPartial = [&db, &store, &tree](int64_t uid, const std::string& key) {
        if (auto acct = tree::account(db, tree, uid)) tree.tempRemove(*acct, key);
        else store.remove(uid, key);
    };

    // ---- Init: create an upload session + empty blob ----
    CROW_ROUTE(app, "/api/uploads/init").methods(crow::HTTPMethod::POST)
    ([&db, &store, &tree, maxFileBytes, dropPartial](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        json body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.is_object()) return http::jsonError(400, "invalid json");
        auto acct = tree::account(db, tree, *userId);
        if (acct) {
            if (!strField(body, "encName").empty() || !strField(body, "encMime").empty() ||
                !strField(body, "wrappedKey").empty()) return tree::noEncryption();
            if (!TreeStore::validUserName(strField(body, "name"))) return http::jsonError(400, "invalid filename");
        }

        // E2E: an encrypted name (opaque) means we store the plaintext name blank.
        std::string encName = strField(body, "encName");
        std::string name;
        if (!encName.empty()) {
            if (!validEncName(encName)) return http::jsonError(400, "invalid enc name");
        } else {
            name = strField(body, "name");
            if (!validName(name)) return http::jsonError(400, "invalid filename");
        }

        // E2E: an encrypted mime (opaque) means we store a generic placeholder.
        std::string encMime = strField(body, "encMime");
        std::string mime;
        if (!encMime.empty()) {
            if (!validEncName(encMime)) return http::jsonError(400, "invalid enc mime");
            mime = "application/octet-stream";
        } else {
            mime = strField(body, "mime");
            if (mime.empty() || mime.size() > 255 || anyControlChar(mime))
                mime = "application/octet-stream";
        }

        // Half-finished uploads count against quota, so drop any left idle for a day.
        for (auto& [uid, key] : db.takeStaleUploads(24 * 3600)) dropPartial(uid, key);

        std::lock_guard<std::mutex> userLk(storage::userLock(*userId));
        int64_t size = intField(body, "size", 0);
        if (size < 0) size = 0;
        if (size > maxFileBytes) return http::jsonError(413, "file too large");
        // size == 0 means "unknown length" (streamed); the per-chunk check in the
        // PUT handler below is the real quota gate for that case.
        if (size > 0 && !db.hasQuotaRoom(*userId, size))
            return http::jsonError(413, "storage quota exceeded");

        int64_t folderId = intField(body, "folderId", 0);
        if (!db.folderExists(*userId, folderId)) return http::jsonError(400, "folder not found");

        // E2E: wrapped per-file key + plaintext size (display), both opaque to us.
        std::string wrappedKey = strField(body, "wrappedKey");
        int64_t plainSize = intField(body, "plainSize", 0);

        std::string uploadId = security::Crypto::randomHex(16);
        std::string storageKey = security::Crypto::randomHex(16);
        // Tree accounts: the key names a temp file in <acct>/.cloud-serv/uploads (same drive as
        // the tree, so finishing is a rename). Blob accounts: the key IS the final blob.
        if (acct) {
            if (int e = tree.tempCreate(*acct, storageKey)) return tree::fail(e);
        } else if (!store.write(*userId, storageKey, nullptr, 0)) {  // create empty blob
            return http::jsonError(500, "storage init failed");
        }
        if (!db.createUploadSession(*userId, uploadId, folderId, name, mime, size, storageKey,
                                    wrappedKey, plainSize, encName, encMime)) {
            dropPartial(*userId, storageKey);
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
    ([&db, &store, &tree, maxFileBytes](const crow::request& req, const std::string& id) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        // Held across the offset check and the append: two copies of one chunk can't
        // both land, and parallel uploads can't jointly overrun the quota.
        std::lock_guard<std::mutex> userLk(storage::userLock(*userId));
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
        // Quota gate: finished files + every in-progress upload (this one included) + this chunk.
        if (!db.hasQuotaRoom(*userId, static_cast<int64_t>(req.body.size())))
            return http::jsonError(413, "storage quota exceeded");

        if (auto acct = tree::account(db, tree, *userId)) {
            if (int e = tree.tempAppend(*acct, s->storage_key, req.body.data(), req.body.size())) return tree::fail(e);
        } else if (!store.append(*userId, s->storage_key, req.body.data(), req.body.size())) {
            return http::jsonError(500, "storage write failed");
        }
        db.setUploadReceived(*userId, id, newReceived);

        return http::jsonSuccess(json{{"received", newReceived}}.dump());
    });

    // ---- Complete: turn the blob into a real file ----
    CROW_ROUTE(app, "/api/uploads/<string>/complete").methods(crow::HTTPMethod::POST)
    ([&db, &store, &tree](const crow::request& req, const std::string& id) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");

        std::lock_guard<std::mutex> userLk(storage::userLock(*userId));
        auto s = db.getUploadSession(*userId, id);
        if (!s) return http::jsonError(404, "not found");

        if (auto acct = tree::account(db, tree, *userId)) {
            if (tree.tempSize(*acct, s->storage_key) != s->received) return http::jsonError(409, "size mismatch");
            if (s->size > 0 && s->received != s->size) return http::jsonError(400, "incomplete upload");
            if (!db.folderExists(*userId, s->folder_id)) return http::jsonError(409, "the destination folder was deleted");
            auto rel = tree::folderRel(db, *userId, s->folder_id);
            if (!rel) return http::jsonError(409, "the destination folder was deleted");
            std::string finalName;
            if (int e = tree.tempPlace(*acct, s->storage_key, *rel, s->name, true, finalName)) return tree::fail(e);
            int64_t fileId = db.addFile(*userId, s->folder_id, finalName, s->mime, s->received, "-",
                                        "", "", "", s->received);
            db.deleteUploadSession(*userId, id);
            if (fileId < 0) return http::jsonError(500, "could not record file (it is on disk; a rescan will index it)");
            notifyUser(*userId, "files");
            return http::jsonSuccess(json{{"file", {{"id", fileId}, {"name", finalName}, {"mime", s->mime},
                                                    {"size", s->received}}}}.dump());
        }

        // Sanity: on-disk size should match what we recorded.
        int64_t onDisk = store.sizeOf(*userId, s->storage_key);
        if (onDisk != s->received) return http::jsonError(409, "size mismatch");
        if (s->size > 0 && s->received != s->size) return http::jsonError(400, "incomplete upload");

        // Display size = plaintext size when the client declared one (E2E),
        // otherwise the bytes received.
        // Display size = the client's plaintext size, kept sane; quota uses bytes on disk.
        int64_t displaySize = s->plain_size > 0 && s->plain_size <= s->received ? s->plain_size : s->received;
        int64_t fileId = db.addFile(*userId, s->folder_id, s->name, s->mime, displaySize,
                                    s->storage_key, s->wrapped_key, s->enc_name, s->enc_mime, s->received);
        if (fileId < 0) return http::jsonError(500, "could not finalize");
        db.deleteUploadSession(*userId, id); // keep the blob; it's now a real file

        json out = {{"id", fileId}, {"name", s->name}, {"mime", s->mime}, {"size", s->received}};
        notifyUser(*userId, "files");
        return http::jsonSuccess(json{{"file", out}}.dump());
    });

    // ---- Abort: discard the partial blob + session ----
    CROW_ROUTE(app, "/api/uploads/<string>").methods(crow::HTTPMethod::DELETE)
    ([&db, dropPartial](const crow::request& req, const std::string& id) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        std::lock_guard<std::mutex> userLk(storage::userLock(*userId));
        auto s = db.getUploadSession(*userId, id);
        if (!s) return http::jsonError(404, "not found");
        dropPartial(*userId, s->storage_key);
        db.deleteUploadSession(*userId, id);
        return http::jsonSuccess(R"({"ok":true})");
    });
}

} // namespace routes
