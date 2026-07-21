#pragma once

#include <string>
#include <cstdint>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ---- Domain models for the cloud suite ----
// Everything a user owns is scoped by user_id. These structs mirror rows in
// the tables CloudDB creates (see schema.sql).

struct User {
    int64_t id = 0;
    std::string email;
    std::string display_name;
    std::string password_hash;   // never serialized to clients
    std::string created_at;

    // Public view — omits password_hash.
    json toJson() const;
};

struct ApiKeyInfo {
    int64_t id = 0;
    int64_t user_id = 0;
    std::string name;            // human label, e.g. "phone"
    std::string prefix;          // shown to the user to identify a key, e.g. "csk_ab12cd34"
    std::string created_at;
    std::string last_used_at;    // empty if never used

    json toJson() const;
};

struct FileMeta {
    int64_t id = 0;
    int64_t user_id = 0;
    int64_t folder_id = 0;       // 0 = root
    std::string name;            // original filename shown to the user
    std::string mime;
    int64_t size = 0;
    std::string storage_key;     // opaque filename on disk (never exposed)
    std::string created_at;
    bool starred = false;

    json toJson() const;
};

struct Note {
    int64_t id = 0;
    int64_t user_id = 0;
    std::string title;
    std::string body;
    std::string created_at;
    std::string updated_at;

    // Full view (with body).
    json toJson() const;
    // List view (title + timestamps, no body) for lighter list responses.
    json toSummaryJson() const;
};

// A folder in a user's tree. parent_id == 0 means top-level (root).
struct Folder {
    int64_t id = 0;
    int64_t user_id = 0;
    int64_t parent_id = 0;   // 0 = root
    std::string name;
    std::string created_at;
    bool starred = false;

    json toJson() const;
};

// An in-progress chunked upload. Bytes stream to <storage_key> on disk; on
// completion a real files row is created pointing at the same blob.
struct UploadSession {
    std::string id;              // opaque upload id given to the client
    int64_t user_id = 0;
    int64_t folder_id = 0;       // destination folder (0 = root)
    std::string name;            // intended display filename
    std::string mime;
    int64_t size = 0;            // expected total bytes (0 if the client didn't say)
    int64_t received = 0;        // bytes written so far
    std::string storage_key;     // blob on disk being appended to
    std::string created_at;
};
