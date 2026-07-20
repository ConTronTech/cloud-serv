#include "routes/notes.h"
#include "security/request_auth.h"

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace routes {

namespace {

const size_t MAX_TITLE = 512;
const size_t MAX_BODY = 1000000; // 1 MB of text per note

bool hasNullByte(const std::string& s) { return s.find('\0') != std::string::npos; }

std::string strField(const json& j, const char* key) {
    if (j.contains(key) && j[key].is_string()) return j[key].get<std::string>();
    return "";
}

// Parse + validate {title?, body?}. Titles/bodies are stored verbatim and only
// ever rendered by clients via textContent / textarea value (never as HTML), so
// we just enforce size + reject null bytes here.
bool parseNoteBody(const crow::request& req, std::string& title, std::string& body,
                   std::string& err) {
    json j = json::parse(req.body, nullptr, false);
    if (j.is_discarded() || !j.is_object()) { err = "invalid json"; return false; }
    title = strField(j, "title");
    body = strField(j, "body");
    if (title.size() > MAX_TITLE) { err = "title too long"; return false; }
    if (body.size() > MAX_BODY) { err = "body too long"; return false; }
    if (hasNullByte(title) || hasNullByte(body)) { err = "invalid characters"; return false; }
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
        std::string title, body, err;
        if (!parseNoteBody(req, title, body, err)) return http::jsonError(400, err);

        int64_t id = db.createNote(*userId, title, body);
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
        std::string title, body, err;
        if (!parseNoteBody(req, title, body, err)) return http::jsonError(400, err);

        if (!db.updateNote(*userId, noteId, title, body))
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
