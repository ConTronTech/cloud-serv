#pragma once

#include <string>
#include <cstdint>
#include <optional>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ---- Domain models for the cloud suite ----
// Everything a user owns is scoped by user_id. These structs mirror rows in
// the tables CloudDB creates (created on first start in src/db/database.cpp).

struct User {
    int64_t id = 0;
    std::string email;
    std::string display_name;
    std::string password_hash;   // scrypt of the client-derived AUTH key (never the real password)
    std::string created_at;
    // ---- E2E key material (all client-generated; server only stores/serves) ----
    std::string kdf_salt;              // salt the client uses to derive keys from the password
    std::string wrapped_dek;          // Data Encryption Key wrapped by the password-derived KEK
    std::string wrapped_dek_recovery; // DEK wrapped by the recovery key
    // ---- Administration (server-managed; never part of the E2E key material) ----
    std::string role = "user";         // "user" | "admin"
    std::string status = "active";     // "active" | "suspended"
    std::optional<int64_t> storage_quota_bytes; // nullopt = unlimited

    // Public view — omits password_hash.
    json toJson() const;
    // Admin listing view: adds server-visible aggregates (bytes used, file
    // count) that are already part of the documented threat model (sizes/
    // counts are metadata the server can see) — never a name or content.
    json toAdminJson(int64_t usedBytes, int64_t fileCount) const;
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
    int64_t size = 0;            // plaintext size (for display); ciphertext on disk may differ
    std::string storage_key;     // opaque filename on disk (never exposed)
    std::string created_at;
    bool starred = false;
    std::string wrapped_key;     // E2E: per-file content key wrapped by the user's DEK ("" = plaintext)
    std::string enc_name;        // E2E: display name encrypted under the DEK ("" = plaintext, see `name`)
    std::string enc_mime;        // E2E: mime type encrypted under the DEK ("" = plaintext, see `mime`)

    json toJson() const;
};

struct Note {
    int64_t id = 0;
    int64_t user_id = 0;
    std::string title;
    std::string body;
    std::string created_at;
    std::string updated_at;
    // E2E: title/body encrypted under the user's DEK ("iv.ct" base64). When set,
    // the plaintext `title`/`body` are blank. Empty = a legacy plaintext note.
    std::string enc_title;
    std::string enc_body;

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
    std::string enc_name;    // E2E: display name encrypted under the DEK ("" = plaintext, see `name`)

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
    int64_t size = 0;            // expected total bytes on the wire (0 if unknown)
    int64_t received = 0;        // bytes written so far
    std::string storage_key;     // blob on disk being appended to
    std::string created_at;
    std::string wrapped_key;     // E2E: wrapped content key (empty = plaintext)
    int64_t plain_size = 0;      // plaintext size for display (0 = use received)
    std::string enc_name;        // E2E: display name encrypted under the DEK ("" = plaintext)
    std::string enc_mime;        // E2E: mime type encrypted under the DEK ("" = plaintext)
    std::string kind;            // "" = one file, "tree-folder" = a folder streamed as tar
};

// The record of a removed account ("backup + temp remove"). The ACCOUNT ITSELF
// stays (status = 'removed', credentials and E2E key material intact) so its
// owner can sign in, see a notice, and later get their data back; only its
// data (folders/files/notes) is gone from the live tables. Everything needed to
// restore it lives in the backup bundle at backup_path (still-encrypted blobs
// + a JSON dump of the former rows), not in this row.
struct RemovedUser {
    int64_t id = 0;
    int64_t original_user_id = 0;
    std::string email;
    std::string display_name;
    std::string backup_path;
    std::string removed_at;
    int64_t removed_by = 0;      // admin user id who performed the removal
    std::string reason;          // optional admin note, shown to the user at login

    json toJson() const;
};
