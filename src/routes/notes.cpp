#include "routes/notes.h"
#include "security/request_auth.h"

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace routes {

namespace {

const size_t MAX_TITLE = 512;
const size_t MAX_BODY = 1000000; // 1 MB of text per note
// Encrypted forms are "iv.ct" base64 (12-byte nonce + 16-byte tag + base64's 4/3
// expansion), so their caps sit above the plaintext caps.
const size_t MAX_ENC_TITLE = 4096;
const size_t MAX_ENC_BODY = 1400000;

// Opaque "iv.ct" base64 blob (same alphabet the E2E file names use).
bool validEnc(const std::string& s, size_t maxLen) {
    if (s.empty() || s.size() > maxLen) return false;
    for (unsigned char c : s) {
        bool okChar = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '.';
        if (!okChar) return false;
    }
    return true;
}

bool hasNullByte(const std::string& s) { return s.find('\0') != std::string::npos; }

std::string strField(const json& j, const char* key) {
    if (j.contains(key) && j[key].is_string()) return j[key].get<std::string>();
    return "";
}

struct NoteInput {
    std::string title, body;          // legacy plaintext note
    std::string encTitle, encBody;    // E2E note (plaintext fields then stay blank)
    bool preserveUpdatedAt = false;
};

// Parse + validate either {title?, body?} (legacy plaintext) or {encTitle,
// encBody} (E2E: opaque ciphertext the server can't read). Mixing the two is
// rejected so a plaintext copy can never ride along with an encrypted note.
bool parseNoteBody(const crow::request& req, NoteInput& in, std::string& err) {
    json j = json::parse(req.body, nullptr, false);
    if (j.is_discarded() || !j.is_object()) { err = "invalid json"; return false; }
    in.title = strField(j, "title");
    in.body = strField(j, "body");
    in.encTitle = strField(j, "encTitle");
    in.encBody = strField(j, "encBody");
    in.preserveUpdatedAt = j.contains("preserveUpdatedAt") && j["preserveUpdatedAt"].is_boolean() &&
                           j["preserveUpdatedAt"].get<bool>();

    const bool encrypted = !in.encTitle.empty() || !in.encBody.empty();
    if (encrypted) {
        if (!in.title.empty() || !in.body.empty()) {
            err = "send either title/body or encTitle/encBody, not both"; return false;
        }
        if (!validEnc(in.encTitle, MAX_ENC_TITLE) || !validEnc(in.encBody, MAX_ENC_BODY)) {
            err = "invalid encrypted note"; return false;
        }
        return true;
    }
    // Legacy plaintext: stored verbatim and only ever rendered by clients via
    // textContent / textarea value (never as HTML), so enforce size + no NULs.
    if (in.title.size() > MAX_TITLE) { err = "title too long"; return false; }
    if (in.body.size() > MAX_BODY) { err = "body too long"; return false; }
    if (hasNullByte(in.title) || hasNullByte(in.body)) { err = "invalid characters"; return false; }
    return true;
}

} // namespace

void registerNoteRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db) {

    // ---- List (summaries) ----
    CROW_ROUTE(app, "/api/notes").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        json notes = json::array();
        for (const auto& n : db.listNotes(*userId)) notes.push_back(n.toSummaryJson());
        return http::jsonSuccess(json{{"notes", notes}}.dump());
    });

    // ---- Create ----
    CROW_ROUTE(app, "/api/notes").methods(crow::HTTPMethod::POST)
    ([&db](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        NoteInput in; std::string err;
        if (!parseNoteBody(req, in, err)) return http::jsonError(400, err);

        int64_t id = db.createNote(*userId, in.title, in.body, in.encTitle, in.encBody);
        if (id < 0) return http::jsonError(500, "could not create note");
        auto note = db.getNote(*userId, id);
        if (!note) return http::jsonError(500, "could not load note");
        return http::jsonSuccess(json{{"note", note->toJson()}}.dump());
    });

    // ---- Read (full) ----
    CROW_ROUTE(app, "/api/notes/<int>").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req, int noteId) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        auto note = db.getNote(*userId, noteId);
        if (!note) return http::jsonError(404, "not found");
        return http::jsonSuccess(json{{"note", note->toJson()}}.dump());
    });

    // ---- Update ----
    CROW_ROUTE(app, "/api/notes/<int>").methods(crow::HTTPMethod::PUT)
    ([&db](const crow::request& req, int noteId) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        NoteInput in; std::string err;
        if (!parseNoteBody(req, in, err)) return http::jsonError(400, err);

        if (!db.updateNote(*userId, noteId, in.title, in.body, in.encTitle, in.encBody, in.preserveUpdatedAt))
            return http::jsonError(404, "not found");
        auto note = db.getNote(*userId, noteId);
        if (!note) return http::jsonError(404, "not found");
        return http::jsonSuccess(json{{"note", note->toJson()}}.dump());
    });

    // ---- Delete ----
    CROW_ROUTE(app, "/api/notes/<int>").methods(crow::HTTPMethod::DELETE)
    ([&db](const crow::request& req, int noteId) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        if (!db.deleteNote(*userId, noteId)) return http::jsonError(404, "not found");
        return http::jsonSuccess(R"({"ok":true})");
    });
}

} // namespace routes
