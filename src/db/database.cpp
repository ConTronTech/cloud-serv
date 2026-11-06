#include "db/database.h"
#include "utils/logger.h"
#include "security/crypto.h"

#include <sqlite3.h>
#include <ctime>
#include <stdexcept>
#include <string>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <sys/stat.h>

// This layer uses the sqlite3 C API directly (libsqlite3). A fresh connection is
// opened per operation — WAL mode makes concurrent connections cheap and safe,
// and it mirrors the original ProjectDB approach without the SQLiteCpp wrapper.
// Read ops take a shared lock; write ops take an exclusive lock.

namespace {

// RAII sqlite3 connection with sane pragmas.
struct Conn {
    sqlite3* h = nullptr;
    explicit Conn(const std::string& path, int flags) {
        if (sqlite3_open_v2(path.c_str(), &h, flags, nullptr) != SQLITE_OK) {
            std::string msg = h ? sqlite3_errmsg(h) : "open failed";
            if (h) sqlite3_close(h);
            throw std::runtime_error(msg);
        }
        sqlite3_busy_timeout(h, 5000);
        sqlite3_exec(h, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
    }
    ~Conn() { if (h) sqlite3_close(h); }
    Conn(const Conn&) = delete;
    Conn& operator=(const Conn&) = delete;
};

// RAII prepared statement with small typed helpers.
struct Stmt {
    sqlite3_stmt* s = nullptr;
    Stmt(sqlite3* h, const char* sql) {
        if (sqlite3_prepare_v2(h, sql, -1, &s, nullptr) != SQLITE_OK) {
            throw std::runtime_error(sqlite3_errmsg(h));
        }
    }
    ~Stmt() { if (s) sqlite3_finalize(s); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    void bind(int i, const std::string& v) {
        sqlite3_bind_text(s, i, v.c_str(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
    }
    void bind(int i, int64_t v) { sqlite3_bind_int64(s, i, v); }
    void bindNull(int i) { sqlite3_bind_null(s, i); }
    // nullopt binds NULL (e.g. an "unlimited" quota).
    void bind(int i, const std::optional<int64_t>& v) {
        if (v.has_value()) sqlite3_bind_int64(s, i, *v);
        else sqlite3_bind_null(s, i);
    }

    bool step() { return sqlite3_step(s) == SQLITE_ROW; }
    void exec() { sqlite3_step(s); }

    int64_t colInt64(int i) { return sqlite3_column_int64(s, i); }
    bool colIsNull(int i) { return sqlite3_column_type(s, i) == SQLITE_NULL; }
    std::optional<int64_t> colOptInt64(int i) {
        return colIsNull(i) ? std::nullopt : std::optional<int64_t>(sqlite3_column_int64(s, i));
    }
    std::string colText(int i) {
        const unsigned char* p = sqlite3_column_text(s, i);
        return p ? reinterpret_cast<const char*>(p) : std::string();
    }
};

int64_t nowEpoch() { return static_cast<int64_t>(::time(nullptr)); }

} // namespace

// ==== Constructor — init DB (WAL) + schema ====

CloudDB::CloudDB(const std::string& dbPath) : dbPath_(dbPath) {
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
        sqlite3_exec(c.h, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);

        const char* schema = R"(
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                kdf_salt TEXT DEFAULT '',
                wrapped_dek TEXT DEFAULT '',
                wrapped_dek_recovery TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                client_ip TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_session_hash ON sessions(token_hash);
            CREATE TABLE IF NOT EXISTS storage_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                requested_bytes INTEGER NOT NULL,
                message TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                decided_at DATETIME,
                decided_by INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code_hash TEXT UNIQUE NOT NULL,
                label TEXT DEFAULT '',
                created_by INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at INTEGER DEFAULT 0,
                used_at DATETIME,
                used_by INTEGER
            );
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                public_key TEXT NOT NULL,
                wrapped_dek TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending',
                created_ip TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
            CREATE TABLE IF NOT EXISTS user_identities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                issuer TEXT NOT NULL,
                subject TEXT NOT NULL,
                email TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(issuer, subject),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_identity_user ON user_identities(user_id);
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT DEFAULT '',
                prefix TEXT NOT NULL,
                key_hash TEXT UNIQUE NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_apikey_hash ON api_keys(key_hash);
            CREATE TABLE IF NOT EXISTS folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                parent_id INTEGER NOT NULL DEFAULT 0,   -- 0 = root
                name TEXT NOT NULL,
                starred INTEGER NOT NULL DEFAULT 0,
                enc_name TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_folders_user ON folders(user_id, parent_id);

            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                folder_id INTEGER NOT NULL DEFAULT 0,   -- 0 = root
                name TEXT NOT NULL,
                mime TEXT DEFAULT 'application/octet-stream',
                size INTEGER DEFAULT 0,
                storage_key TEXT NOT NULL,
                starred INTEGER NOT NULL DEFAULT 0,
                wrapped_key TEXT DEFAULT '',
                enc_name TEXT DEFAULT '',
                enc_mime TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_files_user ON files(user_id, folder_id);
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT DEFAULT '',
                body TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_notes_user ON notes(user_id);
            CREATE TABLE IF NOT EXISTS upload_sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                folder_id INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                mime TEXT DEFAULT 'application/octet-stream',
                size INTEGER DEFAULT 0,
                received INTEGER DEFAULT 0,
                storage_key TEXT NOT NULL,
                wrapped_key TEXT DEFAULT '',
                plain_size INTEGER DEFAULT 0,
                enc_name TEXT DEFAULT '',
                enc_mime TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_uploads_user ON upload_sessions(user_id);
            CREATE TABLE IF NOT EXISTS app_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS removed_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_user_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                display_name TEXT NOT NULL,
                backup_path TEXT NOT NULL,
                removed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                removed_by INTEGER NOT NULL,
                reason TEXT NOT NULL DEFAULT ''
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_removed_original ON removed_users(original_user_id);
        )";
        char* err = nullptr;
        if (sqlite3_exec(c.h, schema, nullptr, nullptr, &err) != SQLITE_OK) {
            std::string msg = err ? err : "schema exec failed";
            sqlite3_free(err);
            throw std::runtime_error(msg);
        }
        // Migration: add files.folder_id to databases created before folders
        // existed. Ignore the "duplicate column" error when it's already there.
        sqlite3_exec(c.h, "ALTER TABLE files ADD COLUMN folder_id INTEGER NOT NULL DEFAULT 0;",
                     nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE upload_sessions ADD COLUMN folder_id INTEGER NOT NULL DEFAULT 0;",
                     nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE files ADD COLUMN starred INTEGER NOT NULL DEFAULT 0;",
                     nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE folders ADD COLUMN starred INTEGER NOT NULL DEFAULT 0;",
                     nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE users ADD COLUMN kdf_salt TEXT DEFAULT '';", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE users ADD COLUMN wrapped_dek TEXT DEFAULT '';", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE users ADD COLUMN wrapped_dek_recovery TEXT DEFAULT '';", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE files ADD COLUMN wrapped_key TEXT DEFAULT '';", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE upload_sessions ADD COLUMN wrapped_key TEXT DEFAULT '';", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE upload_sessions ADD COLUMN plain_size INTEGER DEFAULT 0;", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE files ADD COLUMN enc_name TEXT DEFAULT '';", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE folders ADD COLUMN enc_name TEXT DEFAULT '';", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE upload_sessions ADD COLUMN enc_name TEXT DEFAULT '';", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE files ADD COLUMN enc_mime TEXT DEFAULT '';", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE upload_sessions ADD COLUMN enc_mime TEXT DEFAULT '';", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE removed_users ADD COLUMN reason TEXT NOT NULL DEFAULT '';", nullptr, nullptr, nullptr);
        // Quota counts bytes on disk, never the client-reported display size.
        sqlite3_exec(c.h, "ALTER TABLE files ADD COLUMN stored_size INTEGER NOT NULL DEFAULT -1;", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "UPDATE files SET stored_size = size WHERE stored_size < 0;", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE upload_sessions ADD COLUMN touched_at INTEGER NOT NULL DEFAULT 0;", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "UPDATE upload_sessions SET touched_at = CAST(strftime('%s','now') AS INTEGER) WHERE touched_at = 0;", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE notes ADD COLUMN enc_title TEXT DEFAULT '';", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE notes ADD COLUMN enc_body TEXT DEFAULT '';", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active';", nullptr, nullptr, nullptr);
        // NULL = unlimited; no NOT NULL/default so "no quota set" is distinguishable from "0 bytes".
        sqlite3_exec(c.h, "ALTER TABLE users ADD COLUMN storage_quota_bytes INTEGER;", nullptr, nullptr, nullptr);
        // NULL = user never chose; the server default (FILES_ENCRYPT_DEFAULT) applies.
        sqlite3_exec(c.h, "ALTER TABLE users ADD COLUMN encrypt_files INTEGER;", nullptr, nullptr, nullptr);
        // 0 = account was created through SSO and has no usable local password.
        sqlite3_exec(c.h, "ALTER TABLE users ADD COLUMN local_login INTEGER NOT NULL DEFAULT 1;", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE users ADD COLUMN signup_ip TEXT DEFAULT '';", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE storage_requests ADD COLUMN upload_bytes INTEGER NOT NULL DEFAULT 0;", nullptr, nullptr, nullptr);
        sqlite3_exec(c.h, "ALTER TABLE users ADD COLUMN signup_note TEXT DEFAULT '';", nullptr, nullptr, nullptr);

        // Admin bootstrap: if this DB has no admin yet, promote the earliest
        // (lowest-id) account. Runs every startup but is a no-op once an admin
        // exists; covers both a brand-new DB and one upgraded from before roles
        // existed, with no manual step. Never demotes an existing admin.
        sqlite3_exec(c.h,
            "UPDATE users SET role='admin' "
            "WHERE id = (SELECT MIN(id) FROM users) "
            "AND NOT EXISTS (SELECT 1 FROM users WHERE role='admin');",
            nullptr, nullptr, nullptr);

        utils::Logger::get_instance().info("Database initialized: " + dbPath_);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().fatal("Database init failed: " + std::string(e.what()));
        throw;
    }
}

// ==== Users ====

int64_t CloudDB::createUser(const std::string& email,
                            const std::string& displayName,
                            const std::string& passwordHash) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "INSERT INTO users(email, display_name, password_hash) VALUES(?, ?, ?)");
        q.bind(1, email);
        q.bind(2, displayName);
        q.bind(3, passwordHash);
        if (sqlite3_step(q.s) != SQLITE_DONE) return -1;  // UNIQUE(email) etc.
        int64_t id = sqlite3_last_insert_rowid(c.h);
        // Admin bootstrap: the constructor's copy of this only ever runs once,
        // at startup, before the very first account exists — so it alone can
        // never promote anyone on a fresh DB. Re-check here, after every
        // registration, so the first account created (not just the first DB
        // opened) becomes admin. No-op once any admin exists.
        sqlite3_exec(c.h,
            "UPDATE users SET role='admin' "
            "WHERE id = (SELECT MIN(id) FROM users) "
            "AND NOT EXISTS (SELECT 1 FROM users WHERE role='admin');",
            nullptr, nullptr, nullptr);
        return id;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().warn("createUser: " + std::string(e.what()));
        return -1;
    }
}

std::optional<User> CloudDB::findUserByEmail(const std::string& email) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT id, email, display_name, password_hash, created_at, "
                    "kdf_salt, wrapped_dek, wrapped_dek_recovery, role, status, storage_quota_bytes "
                    "FROM users WHERE email = ?");
        q.bind(1, email);
        if (!q.step()) return std::nullopt;
        User u;
        u.id = q.colInt64(0);
        u.email = q.colText(1);
        u.display_name = q.colText(2);
        u.password_hash = q.colText(3);
        u.created_at = q.colText(4);
        u.kdf_salt = q.colText(5);
        u.wrapped_dek = q.colText(6);
        u.wrapped_dek_recovery = q.colText(7);
        u.role = q.colText(8);
        u.status = q.colText(9);
        u.storage_quota_bytes = q.colOptInt64(10);
        return u;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("findUserByEmail: " + std::string(e.what()));
        return std::nullopt;
    }
}

std::optional<User> CloudDB::findUserById(int64_t id) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT id, email, display_name, password_hash, created_at, "
                    "kdf_salt, wrapped_dek, wrapped_dek_recovery, role, status, storage_quota_bytes "
                    "FROM users WHERE id = ?");
        q.bind(1, id);
        if (!q.step()) return std::nullopt;
        User u;
        u.id = q.colInt64(0);
        u.email = q.colText(1);
        u.display_name = q.colText(2);
        u.password_hash = q.colText(3);
        u.created_at = q.colText(4);
        u.kdf_salt = q.colText(5);
        u.wrapped_dek = q.colText(6);
        u.wrapped_dek_recovery = q.colText(7);
        u.role = q.colText(8);
        u.status = q.colText(9);
        u.storage_quota_bytes = q.colOptInt64(10);
        return u;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("findUserById: " + std::string(e.what()));
        return std::nullopt;
    }
}

bool CloudDB::setUserKeys(int64_t userId, const std::string& kdfSalt,
                          const std::string& wrappedDek, const std::string& wrappedDekRecovery) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE users SET kdf_salt = ?, wrapped_dek = ?, wrapped_dek_recovery = ? "
                    "WHERE id = ?");
        q.bind(1, kdfSalt);
        q.bind(2, wrappedDek);
        q.bind(3, wrappedDekRecovery);
        q.bind(4, userId);
        q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("setUserKeys: " + std::string(e.what()));
        return false;
    }
}

std::optional<std::string> CloudDB::saltForEmail(const std::string& email) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT kdf_salt FROM users WHERE email = ?");
        q.bind(1, email);
        if (!q.step()) return std::nullopt;
        return q.colText(0);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("saltForEmail: " + std::string(e.what()));
        return std::nullopt;
    }
}

std::string CloudDB::serverSecret() {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        {
            Stmt q(c.h, "SELECT value FROM app_meta WHERE key = 'server_secret'");
            if (q.step()) return q.colText(0);
        }
        // First run: generate and persist a random secret.
        std::string secret = security::Crypto::randomHex(32);
        Stmt ins(c.h, "INSERT OR IGNORE INTO app_meta(key, value) VALUES('server_secret', ?)");
        ins.bind(1, secret);
        ins.exec();
        Stmt q2(c.h, "SELECT value FROM app_meta WHERE key = 'server_secret'");
        if (q2.step()) return q2.colText(0);
        return secret;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("serverSecret: " + std::string(e.what()));
        return "";
    }
}

// ==== Sessions ====

bool CloudDB::createSession(int64_t userId, const std::string& tokenHash,
                            const std::string& clientIp, int64_t expiresAt) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "INSERT INTO sessions(user_id, token_hash, client_ip, expires_at) "
                    "VALUES(?, ?, ?, ?)");
        q.bind(1, userId);
        q.bind(2, tokenHash);
        q.bind(3, clientIp);
        q.bind(4, expiresAt);
        return sqlite3_step(q.s) == SQLITE_DONE;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("createSession: " + std::string(e.what()));
        return false;
    }
}

std::optional<int64_t> CloudDB::userForSession(const std::string& tokenHash) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        // Join users to check status on every use: a suspended account's
        // sessions stop working on the very next request, not just future
        // logins — no separate session-revocation step needed to shut it off.
        Stmt q(c.h, "SELECT s.user_id, s.expires_at, u.status FROM sessions s "
                    "JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?");
        q.bind(1, tokenHash);
        if (!q.step()) return std::nullopt;
        int64_t userId = q.colInt64(0);
        int64_t expiresAt = q.colInt64(1);
        std::string status = q.colText(2);
        if (expiresAt < nowEpoch()) return std::nullopt;  // expired
        if (status != "active") return std::nullopt;      // suspended
        return userId;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("userForSession: " + std::string(e.what()));
        return std::nullopt;
    }
}

void CloudDB::deleteSession(const std::string& tokenHash) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "DELETE FROM sessions WHERE token_hash = ?");
        q.bind(1, tokenHash);
        q.exec();
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("deleteSession: " + std::string(e.what()));
    }
}

std::optional<int64_t> CloudDB::userForIdentity(const std::string& issuer, const std::string& subject) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT user_id FROM user_identities WHERE issuer = ? AND subject = ?");
        q.bind(1, issuer); q.bind(2, subject);
        if (!q.step()) return std::nullopt;
        return q.colInt64(0);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("userForIdentity: " + std::string(e.what()));
        return std::nullopt;
    }
}

bool CloudDB::linkIdentity(int64_t userId, const std::string& issuer, const std::string& subject, const std::string& email) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "INSERT INTO user_identities(user_id, issuer, subject, email) VALUES(?, ?, ?, ?)");
        q.bind(1, userId); q.bind(2, issuer); q.bind(3, subject); q.bind(4, email);
        return sqlite3_step(q.s) == SQLITE_DONE;   // UNIQUE(issuer, subject) -> false
    } catch (const std::exception& e) {
        utils::Logger::get_instance().warn("linkIdentity: " + std::string(e.what()));
        return false;
    }
}

std::vector<CloudDB::Identity> CloudDB::listIdentities(int64_t userId) {
    std::shared_lock lock(db_mutex_);
    std::vector<Identity> out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT id, user_id, issuer, subject, email, created_at FROM user_identities WHERE user_id = ? ORDER BY id");
        q.bind(1, userId);
        while (q.step()) {
            Identity i; i.id = q.colInt64(0); i.user_id = q.colInt64(1); i.issuer = q.colText(2);
            i.subject = q.colText(3); i.email = q.colText(4); i.created_at = q.colText(5);
            out.push_back(i);
        }
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("listIdentities: " + std::string(e.what()));
    }
    return out;
}

bool CloudDB::unlinkIdentity(int64_t userId, int64_t identityId) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "DELETE FROM user_identities WHERE id = ? AND user_id = ?");
        q.bind(1, identityId); q.bind(2, userId); q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("unlinkIdentity: " + std::string(e.what()));
        return false;
    }
}

bool CloudDB::setLocalLogin(int64_t userId, bool on) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE users SET local_login = ? WHERE id = ?");
        q.bind(1, static_cast<int64_t>(on ? 1 : 0)); q.bind(2, userId); q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("setLocalLogin: " + std::string(e.what()));
        return false;
    }
}

bool CloudDB::hasLocalLogin(int64_t userId) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT local_login FROM users WHERE id = ?");
        q.bind(1, userId);
        if (!q.step()) return false;
        return q.colInt64(0) != 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("hasLocalLogin: " + std::string(e.what()));
        return false;
    }
}

namespace {
CloudDB::Device readDevice(Stmt& q) {
    CloudDB::Device d;
    d.id = q.colInt64(0); d.user_id = q.colInt64(1); d.name = q.colText(2); d.public_key = q.colText(3);
    d.wrapped_dek = q.colText(4); d.status = q.colText(5); d.created_at = q.colText(6);
    d.last_used_at = q.colText(7); d.created_ip = q.colText(8);
    return d;
}
const char* kDeviceCols = "id, user_id, name, public_key, wrapped_dek, status, created_at, COALESCE(last_used_at,''), created_ip";
} // namespace

namespace {
const char* kSrCols = "r.id, r.user_id, r.requested_bytes, COALESCE(u.email,''), COALESCE(u.display_name,''), r.message, r.status, r.created_at, r.upload_bytes";
CloudDB::StorageRequest readSr(Stmt& q) {
    CloudDB::StorageRequest r;
    r.id = q.colInt64(0); r.user_id = q.colInt64(1); r.requested_bytes = q.colInt64(2); r.email = q.colText(3);
    r.display_name = q.colText(4); r.message = q.colText(5); r.status = q.colText(6); r.created_at = q.colText(7);
    r.upload_bytes = q.colInt64(8);
    return r;
}
} // namespace

int64_t CloudDB::createStorageRequest(int64_t userId, int64_t requestedBytes, int64_t uploadBytes, const std::string& message) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        { Stmt d(c.h, "DELETE FROM storage_requests WHERE user_id = ? AND status = 'pending'"); d.bind(1, userId); d.exec(); }
        Stmt q(c.h, "INSERT INTO storage_requests(user_id, requested_bytes, upload_bytes, message) VALUES(?, ?, ?, ?)");
        q.bind(1, userId); q.bind(2, requestedBytes); q.bind(3, uploadBytes); q.bind(4, message);
        if (sqlite3_step(q.s) != SQLITE_DONE) return -1;
        return sqlite3_last_insert_rowid(c.h);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("createStorageRequest: " + std::string(e.what()));
        return -1;
    }
}

std::vector<CloudDB::StorageRequest> CloudDB::listPendingStorageRequests() {
    std::shared_lock lock(db_mutex_);
    std::vector<StorageRequest> out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        const std::string sql = std::string("SELECT ") + kSrCols + " FROM storage_requests r LEFT JOIN users u ON u.id = r.user_id WHERE r.status = 'pending' ORDER BY r.id";
        Stmt q(c.h, sql.c_str());
        while (q.step()) out.push_back(readSr(q));
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("listPendingStorageRequests: " + std::string(e.what()));
    }
    return out;
}

std::optional<CloudDB::StorageRequest> CloudDB::getStorageRequest(int64_t id) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        const std::string sql = std::string("SELECT ") + kSrCols + " FROM storage_requests r LEFT JOIN users u ON u.id = r.user_id WHERE r.id = ?";
        Stmt q(c.h, sql.c_str());
        q.bind(1, id);
        if (!q.step()) return std::nullopt;
        return readSr(q);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("getStorageRequest: " + std::string(e.what()));
        return std::nullopt;
    }
}

std::optional<CloudDB::StorageRequest> CloudDB::latestStorageRequest(int64_t userId) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        const std::string sql = std::string("SELECT ") + kSrCols + " FROM storage_requests r LEFT JOIN users u ON u.id = r.user_id WHERE r.user_id = ? ORDER BY r.id DESC LIMIT 1";
        Stmt q(c.h, sql.c_str());
        q.bind(1, userId);
        if (!q.step()) return std::nullopt;
        return readSr(q);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("latestStorageRequest: " + std::string(e.what()));
        return std::nullopt;
    }
}

bool CloudDB::decideStorageRequest(int64_t id, const std::string& status, int64_t adminId) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE storage_requests SET status = ?, decided_at = CURRENT_TIMESTAMP, decided_by = ? WHERE id = ? AND status = 'pending'");
        q.bind(1, status); q.bind(2, adminId); q.bind(3, id); q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("decideStorageRequest: " + std::string(e.what()));
        return false;
    }
}

int64_t CloudDB::createInvite(const std::string& codeHash, const std::string& label, int64_t createdBy, int64_t expiresAtEpoch) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "INSERT INTO invites(code_hash, label, created_by, expires_at) VALUES(?, ?, ?, ?)");
        q.bind(1, codeHash); q.bind(2, label); q.bind(3, createdBy); q.bind(4, expiresAtEpoch);
        if (sqlite3_step(q.s) != SQLITE_DONE) return -1;
        return sqlite3_last_insert_rowid(c.h);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("createInvite: " + std::string(e.what()));
        return -1;
    }
}

std::vector<CloudDB::Invite> CloudDB::listInvites() {
    std::shared_lock lock(db_mutex_);
    std::vector<Invite> out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT i.id, i.label, i.created_by, i.created_at, i.expires_at, COALESCE(i.used_at,''), COALESCE(u.email,'') "
                    "FROM invites i LEFT JOIN users u ON u.id = i.used_by ORDER BY i.id DESC LIMIT 200");
        while (q.step()) {
            Invite v; v.id = q.colInt64(0); v.label = q.colText(1); v.created_by = q.colInt64(2); v.created_at = q.colText(3);
            int64_t exp = q.colInt64(4); v.expires_at = exp ? std::to_string(exp) : "";
            v.used_at = q.colText(5); v.used_by_email = q.colText(6);
            out.push_back(v);
        }
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("listInvites: " + std::string(e.what()));
    }
    return out;
}

bool CloudDB::revokeInvite(int64_t id) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "DELETE FROM invites WHERE id = ? AND used_at IS NULL");
        q.bind(1, id); q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("revokeInvite: " + std::string(e.what()));
        return false;
    }
}

std::optional<int64_t> CloudDB::findUsableInvite(const std::string& codeHash) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT id FROM invites WHERE code_hash = ? AND used_at IS NULL "
                    "AND (expires_at = 0 OR expires_at > CAST(strftime('%s','now') AS INTEGER))");
        q.bind(1, codeHash);
        if (!q.step()) return std::nullopt;
        return q.colInt64(0);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("findUsableInvite: " + std::string(e.what()));
        return std::nullopt;
    }
}

bool CloudDB::consumeInvite(int64_t inviteId, int64_t userId) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE invites SET used_at = CURRENT_TIMESTAMP, used_by = ? WHERE id = ? AND used_at IS NULL "
                    "AND (expires_at = 0 OR expires_at > CAST(strftime('%s','now') AS INTEGER))");
        q.bind(1, userId); q.bind(2, inviteId); q.exec();
        return sqlite3_changes(c.h) == 1;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("consumeInvite: " + std::string(e.what()));
        return false;
    }
}

bool CloudDB::setUserStatus(int64_t userId, const std::string& status) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE users SET status = ? WHERE id = ?");
        q.bind(1, status); q.bind(2, userId); q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("setUserStatus: " + std::string(e.what()));
        return false;
    }
}

bool CloudDB::setSignupInfo(int64_t userId, const std::string& ip, const std::string& note) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE users SET signup_ip = ?, signup_note = ? WHERE id = ?");
        q.bind(1, ip); q.bind(2, note); q.bind(3, userId); q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("setSignupInfo: " + std::string(e.what()));
        return false;
    }
}

std::vector<CloudDB::SignupRequest> CloudDB::listPendingSignups() {
    std::shared_lock lock(db_mutex_);
    std::vector<SignupRequest> out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT id, email, display_name, created_at, COALESCE(signup_ip,''), COALESCE(signup_note,'') "
                    "FROM users WHERE status = 'pending' ORDER BY id");
        while (q.step()) {
            SignupRequest r; r.id = q.colInt64(0); r.email = q.colText(1); r.display_name = q.colText(2);
            r.created_at = q.colText(3); r.ip = q.colText(4); r.note = q.colText(5);
            out.push_back(r);
        }
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("listPendingSignups: " + std::string(e.what()));
    }
    return out;
}

bool CloudDB::deletePendingUser(int64_t userId) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        sqlite3_exec(c.h, "PRAGMA foreign_keys = ON;", nullptr, nullptr, nullptr);
        Stmt q(c.h, "DELETE FROM users WHERE id = ? AND status = 'pending'");
        q.bind(1, userId); q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("deletePendingUser: " + std::string(e.what()));
        return false;
    }
}

int CloudDB::countUsersWithStatus(const std::string& status) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT COUNT(*) FROM users WHERE status = ?");
        q.bind(1, status); q.step();
        return static_cast<int>(q.colInt64(0));
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("countUsersWithStatus: " + std::string(e.what()));
        return 0;
    }
}

int64_t CloudDB::createDevice(int64_t userId, const std::string& name, const std::string& publicKey,
                              const std::string& wrappedDek, const std::string& ip) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "INSERT INTO devices(user_id, name, public_key, wrapped_dek, status, created_ip) VALUES(?, ?, ?, ?, ?, ?)");
        q.bind(1, userId); q.bind(2, name); q.bind(3, publicKey); q.bind(4, wrappedDek);
        q.bind(5, std::string(wrappedDek.empty() ? "pending" : "approved")); q.bind(6, ip);
        if (sqlite3_step(q.s) != SQLITE_DONE) return -1;
        return sqlite3_last_insert_rowid(c.h);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("createDevice: " + std::string(e.what()));
        return -1;
    }
}

std::vector<CloudDB::Device> CloudDB::listDevices(int64_t userId) {
    std::shared_lock lock(db_mutex_);
    std::vector<Device> out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        const std::string sql = std::string("SELECT ") + kDeviceCols + " FROM devices WHERE user_id = ? ORDER BY id";
        Stmt q(c.h, sql.c_str());
        q.bind(1, userId);
        while (q.step()) out.push_back(readDevice(q));
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("listDevices: " + std::string(e.what()));
    }
    return out;
}

std::optional<CloudDB::Device> CloudDB::getDevice(int64_t userId, int64_t deviceId) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        const std::string sql = std::string("SELECT ") + kDeviceCols + " FROM devices WHERE user_id = ? AND id = ?";
        Stmt q(c.h, sql.c_str());
        q.bind(1, userId); q.bind(2, deviceId);
        if (!q.step()) return std::nullopt;
        return readDevice(q);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("getDevice: " + std::string(e.what()));
        return std::nullopt;
    }
}

bool CloudDB::approveDevice(int64_t userId, int64_t deviceId, const std::string& wrappedDek) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE devices SET wrapped_dek = ?, status = 'approved' WHERE user_id = ? AND id = ? AND status = 'pending'");
        q.bind(1, wrappedDek); q.bind(2, userId); q.bind(3, deviceId); q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("approveDevice: " + std::string(e.what()));
        return false;
    }
}

bool CloudDB::deleteDevice(int64_t userId, int64_t deviceId) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "DELETE FROM devices WHERE user_id = ? AND id = ?");
        q.bind(1, userId); q.bind(2, deviceId); q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("deleteDevice: " + std::string(e.what()));
        return false;
    }
}

void CloudDB::touchDevice(int64_t userId, int64_t deviceId) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE devices SET last_used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND id = ?");
        q.bind(1, userId); q.bind(2, deviceId); q.exec();
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("touchDevice: " + std::string(e.what()));
    }
}

int CloudDB::countDevices(int64_t userId, const std::string& status) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, status.empty() ? "SELECT COUNT(*) FROM devices WHERE user_id = ?"
                                   : "SELECT COUNT(*) FROM devices WHERE user_id = ? AND status = ?");
        q.bind(1, userId);
        if (!status.empty()) q.bind(2, status);
        q.step();
        return static_cast<int>(q.colInt64(0));
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("countDevices: " + std::string(e.what()));
        return 0;
    }
}

int CloudDB::deleteOtherSessions(int64_t userId, const std::string& keepTokenHash) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "DELETE FROM sessions WHERE user_id = ? AND token_hash != ?");
        q.bind(1, userId);
        q.bind(2, keepTokenHash);
        q.exec();
        return sqlite3_changes(c.h);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("deleteOtherSessions: " + std::string(e.what()));
        return -1;
    }
}

bool CloudDB::setDisplayName(int64_t userId, const std::string& name) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE users SET display_name = ? WHERE id = ?");
        q.bind(1, name); q.bind(2, userId); q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("setDisplayName: " + std::string(e.what()));
        return false;
    }
}

bool CloudDB::setPasswordAndKeys(int64_t userId, const std::string& pwHash,
                                 const std::string& kdfSalt, const std::string& wrappedDek) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE users SET password_hash = ?, kdf_salt = ?, wrapped_dek = ? WHERE id = ?");
        q.bind(1, pwHash); q.bind(2, kdfSalt); q.bind(3, wrappedDek); q.bind(4, userId);
        q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("setPasswordAndKeys: " + std::string(e.what()));
        return false;
    }
}

int CloudDB::purgeExpiredSessions() {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "DELETE FROM sessions WHERE expires_at < ?");
        q.bind(1, nowEpoch());
        q.exec();
        return sqlite3_changes(c.h);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("purgeExpiredSessions: " + std::string(e.what()));
        return 0;
    }
}

// ==== API keys ====

int64_t CloudDB::createApiKey(int64_t userId, const std::string& name,
                              const std::string& prefix, const std::string& keyHash) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "INSERT INTO api_keys(user_id, name, prefix, key_hash) VALUES(?, ?, ?, ?)");
        q.bind(1, userId);
        q.bind(2, name);
        q.bind(3, prefix);
        q.bind(4, keyHash);
        if (sqlite3_step(q.s) != SQLITE_DONE) return -1;
        return sqlite3_last_insert_rowid(c.h);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("createApiKey: " + std::string(e.what()));
        return -1;
    }
}

std::optional<int64_t> CloudDB::userForApiKey(const std::string& keyHash) {
    std::unique_lock lock(db_mutex_);  // also bumps last_used_at (a write)
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        int64_t keyId = 0, userId = 0;
        {
            // Same suspension check as userForSession: a suspended account's API
            // keys stop authenticating immediately, not just its login sessions.
            Stmt q(c.h, "SELECT ak.id, ak.user_id, u.status FROM api_keys ak "
                        "JOIN users u ON u.id = ak.user_id WHERE ak.key_hash = ?");
            q.bind(1, keyHash);
            if (!q.step()) return std::nullopt;
            keyId = q.colInt64(0);
            userId = q.colInt64(1);
            if (q.colText(2) != "active") return std::nullopt;
        }
        Stmt upd(c.h, "UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?");
        upd.bind(1, keyId);
        upd.exec();
        return userId;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("userForApiKey: " + std::string(e.what()));
        return std::nullopt;
    }
}

std::vector<ApiKeyInfo> CloudDB::listApiKeys(int64_t userId) {
    std::shared_lock lock(db_mutex_);
    std::vector<ApiKeyInfo> out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT id, user_id, name, prefix, created_at, COALESCE(last_used_at, '') "
                    "FROM api_keys WHERE user_id = ? ORDER BY created_at DESC");
        q.bind(1, userId);
        while (q.step()) {
            ApiKeyInfo k;
            k.id = q.colInt64(0);
            k.user_id = q.colInt64(1);
            k.name = q.colText(2);
            k.prefix = q.colText(3);
            k.created_at = q.colText(4);
            k.last_used_at = q.colText(5);
            out.push_back(k);
        }
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("listApiKeys: " + std::string(e.what()));
    }
    return out;
}

bool CloudDB::revokeApiKey(int64_t userId, int64_t keyId) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "DELETE FROM api_keys WHERE id = ? AND user_id = ?");
        q.bind(1, keyId);
        q.bind(2, userId);
        q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("revokeApiKey: " + std::string(e.what()));
        return false;
    }
}

// ==== Files (metadata) ====

int64_t CloudDB::addFile(int64_t userId, int64_t folderId, const std::string& name,
                         const std::string& mime, int64_t size, const std::string& storageKey,
                         const std::string& wrappedKey, const std::string& encName,
                         const std::string& encMime, int64_t storedSize) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "INSERT INTO files(user_id, folder_id, name, mime, size, storage_key, wrapped_key, enc_name, enc_mime, stored_size) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        q.bind(10, storedSize < 0 ? size : storedSize);
        q.bind(1, userId);
        q.bind(2, folderId);
        q.bind(3, name);
        q.bind(4, mime);
        q.bind(5, size);
        q.bind(6, storageKey);
        q.bind(7, wrappedKey);
        q.bind(8, encName);
        q.bind(9, encMime);
        if (sqlite3_step(q.s) != SQLITE_DONE) return -1;
        return sqlite3_last_insert_rowid(c.h);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("addFile: " + std::string(e.what()));
        return -1;
    }
}

std::vector<FileMeta> CloudDB::listFiles(int64_t userId, int64_t folderId) {
    std::shared_lock lock(db_mutex_);
    std::vector<FileMeta> out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT id, user_id, folder_id, name, mime, size, storage_key, created_at, starred, wrapped_key, enc_name, enc_mime "
                    "FROM files WHERE user_id = ? AND folder_id = ? ORDER BY name COLLATE NOCASE");
        q.bind(1, userId);
        q.bind(2, folderId);
        while (q.step()) {
            FileMeta f;
            f.id = q.colInt64(0);
            f.user_id = q.colInt64(1);
            f.folder_id = q.colInt64(2);
            f.name = q.colText(3);
            f.mime = q.colText(4);
            f.size = q.colInt64(5);
            f.storage_key = q.colText(6);
            f.created_at = q.colText(7);
            f.starred = q.colInt64(8) != 0; f.wrapped_key = q.colText(9); f.enc_name = q.colText(10); f.enc_mime = q.colText(11);
            out.push_back(f);
        }
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("listFiles: " + std::string(e.what()));
    }
    return out;
}

std::optional<FileMeta> CloudDB::getFile(int64_t userId, int64_t fileId) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT id, user_id, folder_id, name, mime, size, storage_key, created_at, starred, wrapped_key, enc_name, enc_mime "
                    "FROM files WHERE id = ? AND user_id = ?");
        q.bind(1, fileId);
        q.bind(2, userId);
        if (!q.step()) return std::nullopt;
        FileMeta f;
        f.id = q.colInt64(0);
        f.user_id = q.colInt64(1);
        f.folder_id = q.colInt64(2);
        f.name = q.colText(3);
        f.mime = q.colText(4);
        f.size = q.colInt64(5);
        f.storage_key = q.colText(6);
        f.created_at = q.colText(7);
        f.starred = q.colInt64(8) != 0; f.wrapped_key = q.colText(9); f.enc_name = q.colText(10); f.enc_mime = q.colText(11);
        return f;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("getFile: " + std::string(e.what()));
        return std::nullopt;
    }
}

bool CloudDB::moveFile(int64_t userId, int64_t fileId, int64_t folderId) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE files SET folder_id = ? WHERE id = ? AND user_id = ?");
        q.bind(1, folderId);
        q.bind(2, fileId);
        q.bind(3, userId);
        q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("moveFile: " + std::string(e.what()));
        return false;
    }
}

bool CloudDB::renameFile(int64_t userId, int64_t fileId, const std::string& name,
                         const std::string& encName) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        // E2E: when the client sends an encrypted name, we store it opaque and
        // blank the plaintext column; otherwise the legacy plaintext path.
        Stmt q(c.h, encName.empty()
                        ? "UPDATE files SET name = ? WHERE id = ? AND user_id = ?"
                        : "UPDATE files SET enc_name = ?, name = '' WHERE id = ? AND user_id = ?");
        q.bind(1, encName.empty() ? name : encName);
        q.bind(2, fileId);
        q.bind(3, userId);
        q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("renameFile: " + std::string(e.what()));
        return false;
    }
}

bool CloudDB::deleteFile(int64_t userId, int64_t fileId) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "DELETE FROM files WHERE id = ? AND user_id = ?");
        q.bind(1, fileId);
        q.bind(2, userId);
        q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("deleteFile: " + std::string(e.what()));
        return false;
    }
}

// ==== Aggregates / search ====

std::pair<int64_t, int64_t> CloudDB::usage(int64_t userId) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT COALESCE(SUM(stored_size), 0), COUNT(*) FROM files WHERE user_id = ?");
        q.bind(1, userId);
        if (q.step()) return { q.colInt64(0), q.colInt64(1) };
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("usage: " + std::string(e.what()));
    }
    return { 0, 0 };
}

// Escape LIKE wildcards in user input and wrap with %...% for a substring match.
static std::string likeTerm(const std::string& q) {
    std::string term = "%";
    for (char ch : q) {
        if (ch == '%' || ch == '_' || ch == '\\') term += '\\';
        term += ch;
    }
    return term + "%";
}

std::vector<FileMeta> CloudDB::searchFiles(int64_t userId, const std::string& q,
                                           const std::string& category, int limit) {
    std::shared_lock lock(db_mutex_);
    std::vector<FileMeta> out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        std::string sql =
            "SELECT id, user_id, folder_id, name, mime, size, storage_key, created_at, starred, wrapped_key, enc_name, enc_mime "
            "FROM files WHERE user_id = ?";
        if (!q.empty()) sql += " AND name LIKE ? ESCAPE '\\'";
        if (category == "image")         sql += " AND mime LIKE 'image/%'";
        else if (category == "video")    sql += " AND mime LIKE 'video/%'";
        else if (category == "audio")    sql += " AND mime LIKE 'audio/%'";
        else if (category == "document") sql += " AND (mime LIKE 'text/%' OR mime LIKE 'application/%')";
        else if (category == "other")
            sql += " AND mime NOT LIKE 'image/%' AND mime NOT LIKE 'video/%'"
                   " AND mime NOT LIKE 'audio/%' AND mime NOT LIKE 'text/%'"
                   " AND mime NOT LIKE 'application/%'";
        sql += " ORDER BY created_at DESC LIMIT ?";

        Stmt st(c.h, sql.c_str());
        int idx = 1;
        st.bind(idx++, userId);
        if (!q.empty()) st.bind(idx++, likeTerm(q));
        st.bind(idx++, static_cast<int64_t>(limit > 0 ? limit : 500));
        while (st.step()) {
            FileMeta f;
            f.id = st.colInt64(0);
            f.user_id = st.colInt64(1);
            f.folder_id = st.colInt64(2);
            f.name = st.colText(3);
            f.mime = st.colText(4);
            f.size = st.colInt64(5);
            f.storage_key = st.colText(6);
            f.created_at = st.colText(7);
            f.starred = st.colInt64(8) != 0; f.wrapped_key = st.colText(9); f.enc_name = st.colText(10); f.enc_mime = st.colText(11);
            out.push_back(f);
        }
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("searchFiles: " + std::string(e.what()));
    }
    return out;
}

std::vector<Folder> CloudDB::searchFolders(int64_t userId, const std::string& q, int limit) {
    std::shared_lock lock(db_mutex_);
    std::vector<Folder> out;
    if (q.empty()) return out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt st(c.h, "SELECT id, user_id, parent_id, name, created_at, starred, enc_name FROM folders "
                     "WHERE user_id = ? AND name LIKE ? ESCAPE '\\' "
                     "ORDER BY name COLLATE NOCASE LIMIT ?");
        st.bind(1, userId);
        st.bind(2, likeTerm(q));
        st.bind(3, static_cast<int64_t>(limit > 0 ? limit : 200));
        while (st.step()) {
            Folder f;
            f.id = st.colInt64(0);
            f.user_id = st.colInt64(1);
            f.parent_id = st.colInt64(2);
            f.name = st.colText(3);
            f.created_at = st.colText(4);
            f.starred = st.colInt64(5) != 0; f.enc_name = st.colText(6);
            out.push_back(f);
        }
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("searchFolders: " + std::string(e.what()));
    }
    return out;
}

// ==== Starred / recent ====

bool CloudDB::setFileStarred(int64_t userId, int64_t fileId, bool starred) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE files SET starred = ? WHERE id = ? AND user_id = ?");
        q.bind(1, static_cast<int64_t>(starred ? 1 : 0));
        q.bind(2, fileId);
        q.bind(3, userId);
        q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("setFileStarred: " + std::string(e.what()));
        return false;
    }
}

bool CloudDB::setFolderStarred(int64_t userId, int64_t folderId, bool starred) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE folders SET starred = ? WHERE id = ? AND user_id = ?");
        q.bind(1, static_cast<int64_t>(starred ? 1 : 0));
        q.bind(2, folderId);
        q.bind(3, userId);
        q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("setFolderStarred: " + std::string(e.what()));
        return false;
    }
}

std::vector<FileMeta> CloudDB::starredFiles(int64_t userId) {
    std::shared_lock lock(db_mutex_);
    std::vector<FileMeta> out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT id, user_id, folder_id, name, mime, size, storage_key, created_at, starred, wrapped_key, enc_name, enc_mime "
                    "FROM files WHERE user_id = ? AND starred = 1 ORDER BY name COLLATE NOCASE");
        q.bind(1, userId);
        while (q.step()) {
            FileMeta f;
            f.id = q.colInt64(0); f.user_id = q.colInt64(1); f.folder_id = q.colInt64(2);
            f.name = q.colText(3); f.mime = q.colText(4); f.size = q.colInt64(5);
            f.storage_key = q.colText(6); f.created_at = q.colText(7); f.starred = q.colInt64(8) != 0; f.wrapped_key = q.colText(9); f.enc_name = q.colText(10); f.enc_mime = q.colText(11);
            out.push_back(f);
        }
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("starredFiles: " + std::string(e.what()));
    }
    return out;
}

std::vector<Folder> CloudDB::starredFolders(int64_t userId) {
    std::shared_lock lock(db_mutex_);
    std::vector<Folder> out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT id, user_id, parent_id, name, created_at, starred, enc_name FROM folders "
                    "WHERE user_id = ? AND starred = 1 ORDER BY name COLLATE NOCASE");
        q.bind(1, userId);
        while (q.step()) {
            Folder f;
            f.id = q.colInt64(0); f.user_id = q.colInt64(1); f.parent_id = q.colInt64(2);
            f.name = q.colText(3); f.created_at = q.colText(4); f.starred = q.colInt64(5) != 0; f.enc_name = q.colText(6);
            out.push_back(f);
        }
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("starredFolders: " + std::string(e.what()));
    }
    return out;
}

std::vector<FileMeta> CloudDB::recentFiles(int64_t userId, int limit) {
    std::shared_lock lock(db_mutex_);
    std::vector<FileMeta> out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT id, user_id, folder_id, name, mime, size, storage_key, created_at, starred, wrapped_key, enc_name, enc_mime "
                    "FROM files WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT ?");
        q.bind(1, userId);
        q.bind(2, static_cast<int64_t>(limit > 0 ? limit : 50));
        while (q.step()) {
            FileMeta f;
            f.id = q.colInt64(0); f.user_id = q.colInt64(1); f.folder_id = q.colInt64(2);
            f.name = q.colText(3); f.mime = q.colText(4); f.size = q.colInt64(5);
            f.storage_key = q.colText(6); f.created_at = q.colText(7); f.starred = q.colInt64(8) != 0; f.wrapped_key = q.colText(9); f.enc_name = q.colText(10); f.enc_mime = q.colText(11);
            out.push_back(f);
        }
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("recentFiles: " + std::string(e.what()));
    }
    return out;
}

// ==== Folders ====

bool CloudDB::folderExists(int64_t userId, int64_t folderId) {
    if (folderId == 0) return true; // root is implicit
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT 1 FROM folders WHERE id = ? AND user_id = ?");
        q.bind(1, folderId);
        q.bind(2, userId);
        return q.step();
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("folderExists: " + std::string(e.what()));
        return false;
    }
}

int64_t CloudDB::createFolder(int64_t userId, int64_t parentId, const std::string& name,
                              const std::string& encName) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        if (parentId != 0) {
            Stmt chk(c.h, "SELECT 1 FROM folders WHERE id = ? AND user_id = ?");
            chk.bind(1, parentId);
            chk.bind(2, userId);
            if (!chk.step()) return -1; // parent must exist and be owned
        }
        Stmt q(c.h, "INSERT INTO folders(user_id, parent_id, name, enc_name) VALUES(?, ?, ?, ?)");
        q.bind(1, userId);
        q.bind(2, parentId);
        q.bind(3, name);
        q.bind(4, encName);
        if (sqlite3_step(q.s) != SQLITE_DONE) return -1;
        return sqlite3_last_insert_rowid(c.h);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("createFolder: " + std::string(e.what()));
        return -1;
    }
}

std::vector<Folder> CloudDB::listFolders(int64_t userId, int64_t parentId) {
    std::shared_lock lock(db_mutex_);
    std::vector<Folder> out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT id, user_id, parent_id, name, created_at, starred, enc_name FROM folders "
                    "WHERE user_id = ? AND parent_id = ? ORDER BY name COLLATE NOCASE");
        q.bind(1, userId);
        q.bind(2, parentId);
        while (q.step()) {
            Folder f;
            f.id = q.colInt64(0);
            f.user_id = q.colInt64(1);
            f.parent_id = q.colInt64(2);
            f.name = q.colText(3);
            f.created_at = q.colText(4);
            f.starred = q.colInt64(5) != 0; f.enc_name = q.colText(6);
            out.push_back(f);
        }
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("listFolders: " + std::string(e.what()));
    }
    return out;
}

std::optional<Folder> CloudDB::getFolder(int64_t userId, int64_t folderId) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT id, user_id, parent_id, name, created_at, starred, enc_name FROM folders "
                    "WHERE id = ? AND user_id = ?");
        q.bind(1, folderId);
        q.bind(2, userId);
        if (!q.step()) return std::nullopt;
        Folder f;
        f.id = q.colInt64(0);
        f.user_id = q.colInt64(1);
        f.parent_id = q.colInt64(2);
        f.name = q.colText(3);
        f.created_at = q.colText(4);
        f.starred = q.colInt64(5) != 0; f.enc_name = q.colText(6);
        return f;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("getFolder: " + std::string(e.what()));
        return std::nullopt;
    }
}

bool CloudDB::renameFolder(int64_t userId, int64_t folderId, const std::string& name,
                           const std::string& encName) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, encName.empty()
                        ? "UPDATE folders SET name = ? WHERE id = ? AND user_id = ?"
                        : "UPDATE folders SET enc_name = ?, name = '' WHERE id = ? AND user_id = ?");
        q.bind(1, encName.empty() ? name : encName);
        q.bind(2, folderId);
        q.bind(3, userId);
        q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("renameFolder: " + std::string(e.what()));
        return false;
    }
}

bool CloudDB::moveFolder(int64_t userId, int64_t folderId, int64_t newParentId) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        if (folderId == newParentId) return false; // can't parent to self
        if (newParentId != 0) {
            Stmt chk(c.h, "SELECT 1 FROM folders WHERE id = ? AND user_id = ?");
            chk.bind(1, newParentId);
            chk.bind(2, userId);
            if (!chk.step()) return false; // target must exist and be owned

            // Cycle guard: walk up from the target; if we reach folderId, the
            // move would put a folder inside its own subtree.
            int64_t cur = newParentId, guard = 0;
            while (cur != 0 && guard++ < 100000) {
                if (cur == folderId) return false;
                Stmt up(c.h, "SELECT parent_id FROM folders WHERE id = ? AND user_id = ?");
                up.bind(1, cur);
                up.bind(2, userId);
                if (!up.step()) break;
                cur = up.colInt64(0);
            }
        }
        Stmt q(c.h, "UPDATE folders SET parent_id = ? WHERE id = ? AND user_id = ?");
        q.bind(1, newParentId);
        q.bind(2, folderId);
        q.bind(3, userId);
        q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("moveFolder: " + std::string(e.what()));
        return false;
    }
}

bool CloudDB::deleteFolderRecursive(int64_t userId, int64_t folderId,
                                    std::vector<std::string>& storageKeys) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);

        // Collect the blob keys of every file under this folder (any depth), so
        // the caller can unlink them from disk.
        const char* collectSql =
            "WITH RECURSIVE sub(id) AS ("
            "  SELECT id FROM folders WHERE id = ?1 AND user_id = ?2"
            "  UNION ALL"
            "  SELECT f.id FROM folders f JOIN sub ON f.parent_id = sub.id WHERE f.user_id = ?2"
            ") SELECT storage_key FROM files WHERE user_id = ?2 AND folder_id IN (SELECT id FROM sub)";
        {
            Stmt q(c.h, collectSql);
            q.bind(1, folderId);
            q.bind(2, userId);
            while (q.step()) storageKeys.push_back(q.colText(0));
        }

        if (sqlite3_exec(c.h, "BEGIN", nullptr, nullptr, nullptr) != SQLITE_OK) {
            storageKeys.clear();
            return false;
        }
        const char* delFilesSql =
            "WITH RECURSIVE sub(id) AS ("
            "  SELECT id FROM folders WHERE id = ?1 AND user_id = ?2"
            "  UNION ALL"
            "  SELECT f.id FROM folders f JOIN sub ON f.parent_id = sub.id WHERE f.user_id = ?2"
            ") DELETE FROM files WHERE user_id = ?2 AND folder_id IN (SELECT id FROM sub)";
        { Stmt q(c.h, delFilesSql); q.bind(1, folderId); q.bind(2, userId); q.exec(); }

        const char* delFoldersSql =
            "WITH RECURSIVE sub(id) AS ("
            "  SELECT id FROM folders WHERE id = ?1 AND user_id = ?2"
            "  UNION ALL"
            "  SELECT f.id FROM folders f JOIN sub ON f.parent_id = sub.id WHERE f.user_id = ?2"
            ") DELETE FROM folders WHERE user_id = ?2 AND id IN (SELECT id FROM sub)";
        int changes = 0;
        { Stmt q(c.h, delFoldersSql); q.bind(1, folderId); q.bind(2, userId); q.exec(); changes = sqlite3_changes(c.h); }
        if (sqlite3_exec(c.h, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK) {
            // COMMIT failed (e.g. disk full). Roll back and report failure so the
            // caller never unlinks blobs whose DB rows still exist (data loss).
            sqlite3_exec(c.h, "ROLLBACK", nullptr, nullptr, nullptr);
            storageKeys.clear();
            return false;
        }
        return changes > 0;
    } catch (const std::exception& e) {
        // The Conn destructor closes the connection, which auto-rolls-back any
        // open transaction. Clear the keys so a caller never unlinks blobs whose
        // rows may still exist.
        utils::Logger::get_instance().error("deleteFolderRecursive: " + std::string(e.what()));
        storageKeys.clear();
        return false;
    }
}

std::vector<Folder> CloudDB::folderPath(int64_t userId, int64_t folderId) {
    std::vector<Folder> chain;
    int64_t cur = folderId, guard = 0;
    while (cur != 0 && guard++ < 100000) {
        auto f = getFolder(userId, cur);
        if (!f) break;
        chain.push_back(*f);
        cur = f->parent_id;
    }
    std::reverse(chain.begin(), chain.end()); // root-first
    return chain;
}

// ==== Chunked uploads ====

bool CloudDB::createUploadSession(int64_t userId, const std::string& id, int64_t folderId,
                                  const std::string& name, const std::string& mime,
                                  int64_t size, const std::string& storageKey,
                                  const std::string& wrappedKey, int64_t plainSize,
                                  const std::string& encName, const std::string& encMime) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "INSERT INTO upload_sessions(id, user_id, folder_id, name, mime, size, received, "
                    "storage_key, wrapped_key, plain_size, enc_name, enc_mime, touched_at) "
                    "VALUES(?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, CAST(strftime('%s','now') AS INTEGER))");
        q.bind(1, id);
        q.bind(2, userId);
        q.bind(3, folderId);
        q.bind(4, name);
        q.bind(5, mime);
        q.bind(6, size);
        q.bind(7, storageKey);
        q.bind(8, wrappedKey);
        q.bind(9, plainSize);
        q.bind(10, encName);
        q.bind(11, encMime);
        return sqlite3_step(q.s) == SQLITE_DONE;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("createUploadSession: " + std::string(e.what()));
        return false;
    }
}

std::optional<UploadSession> CloudDB::getUploadSession(int64_t userId, const std::string& id) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT id, user_id, folder_id, name, mime, size, received, storage_key, created_at, "
                    "wrapped_key, plain_size, enc_name, enc_mime FROM upload_sessions WHERE id = ? AND user_id = ?");
        q.bind(1, id);
        q.bind(2, userId);
        if (!q.step()) return std::nullopt;
        UploadSession u;
        u.id = q.colText(0);
        u.user_id = q.colInt64(1);
        u.folder_id = q.colInt64(2);
        u.name = q.colText(3);
        u.mime = q.colText(4);
        u.size = q.colInt64(5);
        u.received = q.colInt64(6);
        u.storage_key = q.colText(7);
        u.created_at = q.colText(8);
        u.wrapped_key = q.colText(9);
        u.plain_size = q.colInt64(10);
        u.enc_name = q.colText(11);
        u.enc_mime = q.colText(12);
        return u;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("getUploadSession: " + std::string(e.what()));
        return std::nullopt;
    }
}

bool CloudDB::setUploadReceived(int64_t userId, const std::string& id, int64_t received) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE upload_sessions SET received = ?, touched_at = CAST(strftime('%s','now') AS INTEGER) WHERE id = ? AND user_id = ?");
        q.bind(1, received);
        q.bind(2, id);
        q.bind(3, userId);
        q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("setUploadReceived: " + std::string(e.what()));
        return false;
    }
}

std::vector<std::pair<int64_t, std::string>> CloudDB::takeStaleUploads(int64_t maxAgeSeconds) {
    std::unique_lock lock(db_mutex_);
    std::vector<std::pair<int64_t, std::string>> out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "SELECT user_id, storage_key FROM upload_sessions "
                    "WHERE touched_at < CAST(strftime('%s','now') AS INTEGER) - ?");
        q.bind(1, maxAgeSeconds);
        while (q.step()) out.emplace_back(q.colInt64(0), q.colText(1));
        Stmt d(c.h, "DELETE FROM upload_sessions WHERE touched_at < CAST(strftime('%s','now') AS INTEGER) - ?");
        d.bind(1, maxAgeSeconds);
        d.exec();
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("takeStaleUploads: " + std::string(e.what()));
        out.clear();
    }
    return out;
}

bool CloudDB::deleteUploadSession(int64_t userId, const std::string& id) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "DELETE FROM upload_sessions WHERE id = ? AND user_id = ?");
        q.bind(1, id);
        q.bind(2, userId);
        q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("deleteUploadSession: " + std::string(e.what()));
        return false;
    }
}

// ==== Notes ====

int64_t CloudDB::createNote(int64_t userId, const std::string& title, const std::string& body,
                           const std::string& encTitle, const std::string& encBody) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "INSERT INTO notes(user_id, title, body, enc_title, enc_body) VALUES(?, ?, ?, ?, ?)");
        q.bind(1, userId);
        q.bind(2, title);
        q.bind(3, body);
        q.bind(4, encTitle);
        q.bind(5, encBody);
        if (sqlite3_step(q.s) != SQLITE_DONE) return -1;
        return sqlite3_last_insert_rowid(c.h);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("createNote: " + std::string(e.what()));
        return -1;
    }
}

std::vector<Note> CloudDB::listNotes(int64_t userId) {
    std::shared_lock lock(db_mutex_);
    std::vector<Note> out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        // Summaries only (no body) — ordered by most recently edited.
        Stmt q(c.h, "SELECT id, user_id, title, created_at, updated_at, enc_title "
                    "FROM notes WHERE user_id = ? ORDER BY updated_at DESC, id DESC");
        q.bind(1, userId);
        while (q.step()) {
            Note n;
            n.id = q.colInt64(0);
            n.user_id = q.colInt64(1);
            n.title = q.colText(2);
            n.created_at = q.colText(3);
            n.updated_at = q.colText(4);
            n.enc_title = q.colText(5);
            out.push_back(n);
        }
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("listNotes: " + std::string(e.what()));
    }
    return out;
}

std::optional<Note> CloudDB::getNote(int64_t userId, int64_t noteId) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT id, user_id, title, body, created_at, updated_at, enc_title, enc_body "
                    "FROM notes WHERE id = ? AND user_id = ?");
        q.bind(1, noteId);
        q.bind(2, userId);
        if (!q.step()) return std::nullopt;
        Note n;
        n.id = q.colInt64(0);
        n.user_id = q.colInt64(1);
        n.title = q.colText(2);
        n.body = q.colText(3);
        n.created_at = q.colText(4);
        n.updated_at = q.colText(5);
        n.enc_title = q.colText(6);
        n.enc_body = q.colText(7);
        return n;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("getNote: " + std::string(e.what()));
        return std::nullopt;
    }
}

bool CloudDB::updateNote(int64_t userId, int64_t noteId,
                         const std::string& title, const std::string& body,
                         const std::string& encTitle, const std::string& encBody,
                         bool preserveUpdatedAt) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, preserveUpdatedAt
            ? "UPDATE notes SET title = ?, body = ?, enc_title = ?, enc_body = ? "
              "WHERE id = ? AND user_id = ?"
            : "UPDATE notes SET title = ?, body = ?, enc_title = ?, enc_body = ?, "
              "updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?");
        q.bind(1, title);
        q.bind(2, body);
        q.bind(3, encTitle);
        q.bind(4, encBody);
        q.bind(5, noteId);
        q.bind(6, userId);
        q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("updateNote: " + std::string(e.what()));
        return false;
    }
}

bool CloudDB::deleteNote(int64_t userId, int64_t noteId) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "DELETE FROM notes WHERE id = ? AND user_id = ?");
        q.bind(1, noteId);
        q.bind(2, userId);
        q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("deleteNote: " + std::string(e.what()));
        return false;
    }
}

// ==== Administration ====

std::vector<User> CloudDB::listAllUsers() {
    std::shared_lock lock(db_mutex_);
    std::vector<User> out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        // password_hash is selected (struct parity with findUser*) but never
        // leaves this layer — User::toJson()/toAdminJson() both omit it.
        Stmt q(c.h, "SELECT id, email, display_name, password_hash, created_at, "
                    "kdf_salt, wrapped_dek, wrapped_dek_recovery, role, status, storage_quota_bytes "
                    "FROM users ORDER BY id DESC");
        while (q.step()) {
            User u;
            u.id = q.colInt64(0);
            u.email = q.colText(1);
            u.display_name = q.colText(2);
            u.password_hash = q.colText(3);
            u.created_at = q.colText(4);
            u.kdf_salt = q.colText(5);
            u.wrapped_dek = q.colText(6);
            u.wrapped_dek_recovery = q.colText(7);
            u.role = q.colText(8);
            u.status = q.colText(9);
            u.storage_quota_bytes = q.colOptInt64(10);
            out.push_back(std::move(u));
        }
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("listAllUsers: " + std::string(e.what()));
    }
    return out;
}

bool CloudDB::setUserRole(int64_t userId, const std::string& role) {
    if (role != "user" && role != "admin") return false;
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE users SET role = ? WHERE id = ?");
        q.bind(1, role);
        q.bind(2, userId);
        q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("setUserRole: " + std::string(e.what()));
        return false;
    }
}

bool CloudDB::setUserSuspended(int64_t userId, bool suspended) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        // Never touches a removed account: that state is left only by restore/wipe.
        Stmt q(c.h, "UPDATE users SET status = ? WHERE id = ? AND status != 'removed'");
        q.bind(1, std::string(suspended ? "suspended" : "active"));
        q.bind(2, userId);
        q.exec();
        if (sqlite3_changes(c.h) == 0) return false;
        // Belt-and-braces: also drop existing sessions so a client that's
        // already holding a cookie/token doesn't linger until it happens to
        // make a request that reaches the userForSession status check (it
        // always would, but there is no reason to leave live rows around).
        if (suspended) {
            Stmt del(c.h, "DELETE FROM sessions WHERE user_id = ?");
            del.bind(1, userId);
            del.exec();
        }
        return true;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("setUserSuspended: " + std::string(e.what()));
        return false;
    }
}

bool CloudDB::setUserQuota(int64_t userId, std::optional<int64_t> quotaBytes) {
    if (quotaBytes.has_value() && *quotaBytes < 0) return false;
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE users SET storage_quota_bytes = ? WHERE id = ?");
        q.bind(1, quotaBytes);
        q.bind(2, userId);
        q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("setUserQuota: " + std::string(e.what()));
        return false;
    }
}

std::optional<bool> CloudDB::getEncryptFiles(int64_t userId) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT encrypt_files FROM users WHERE id = ?");
        q.bind(1, userId);
        if (!q.step()) return std::nullopt;
        auto v = q.colOptInt64(0);
        if (!v) return std::nullopt;
        return *v != 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("getEncryptFiles: " + std::string(e.what()));
        return std::nullopt;
    }
}

bool CloudDB::setEncryptFiles(int64_t userId, bool on) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE users SET encrypt_files = ? WHERE id = ?");
        q.bind(1, static_cast<int64_t>(on ? 1 : 0));
        q.bind(2, userId);
        q.exec();
        return sqlite3_changes(c.h) > 0;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("setEncryptFiles: " + std::string(e.what()));
        return false;
    }
}

int CloudDB::countAdmins() {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'");
        if (!q.step()) return 0;
        return static_cast<int>(q.colInt64(0));
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("countAdmins: " + std::string(e.what()));
        return 0;
    }
}

bool CloudDB::hasQuotaRoom(int64_t userId, int64_t additionalBytes) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        // Finished files plus the bytes of uploads still in progress.
        Stmt q(c.h, "SELECT storage_quota_bytes, "
                    "(SELECT COALESCE(SUM(stored_size), 0) FROM files WHERE user_id = ?) + "
                    "(SELECT COALESCE(SUM(received), 0) FROM upload_sessions WHERE user_id = ?) "
                    "FROM users WHERE id = ?");
        q.bind(1, userId);
        q.bind(2, userId);
        q.bind(3, userId);
        if (!q.step()) return true;  // unknown user: let the route's own auth check reject it
        auto quota = q.colOptInt64(0);
        if (!quota.has_value()) return true;  // unlimited
        int64_t used = q.colInt64(1);
        if (additionalBytes < 0) additionalBytes = 0;
        return used + additionalBytes <= *quota;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("hasQuotaRoom: " + std::string(e.what()));
        return true;  // fail open on a DB error here, same as the rest of this layer
    }
}

// ==== Account lifecycle (admin remove / restore / wipe) ====

namespace {

// Every row of `sql` (one int64 bound to ?1) as a JSON array of objects keyed
// by column name. Generic on purpose: a backup must not silently miss a column
// that a later migration adds. Throws on any step error other than "done" so a
// half-read table can never be mistaken for a complete backup.
json dumpRows(sqlite3* h, const char* sql, int64_t id) {
    json rows = json::array();
    Stmt q(h, sql);
    q.bind(1, id);
    int rc;
    while ((rc = sqlite3_step(q.s)) == SQLITE_ROW) {
        json row = json::object();
        const int n = sqlite3_column_count(q.s);
        for (int i = 0; i < n; ++i) {
            const char* name = sqlite3_column_name(q.s, i);
            switch (sqlite3_column_type(q.s, i)) {
                case SQLITE_INTEGER: row[name] = sqlite3_column_int64(q.s, i); break;
                case SQLITE_FLOAT:   row[name] = sqlite3_column_double(q.s, i); break;
                case SQLITE_NULL:    row[name] = nullptr; break;
                default:             row[name] = q.colText(i); break;  // TEXT (no BLOB columns exist)
            }
        }
        rows.push_back(std::move(row));
    }
    if (rc != SQLITE_DONE) throw std::runtime_error("dumpRows: " + std::string(sqlite3_errmsg(h)));
    return rows;
}

bool execOk(sqlite3* h, const char* sql) {
    return sqlite3_exec(h, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
}

// Run one statement with a single int64 bound to ?1; true only on a clean DONE
// (and, when requireChange, at least one row affected).
bool execBound(sqlite3* h, const char* sql, int64_t id, bool requireChange = false) {
    Stmt q(h, sql);
    q.bind(1, id);
    if (sqlite3_step(q.s) != SQLITE_DONE) return false;
    return !requireChange || sqlite3_changes(h) > 0;
}

// Blob keys are server-generated hex; never trust one read back from a file.
bool safeBlobKey(const std::string& key) {
    if (key.empty() || key.size() > 128) return false;
    for (char c : key) {
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return true;
}

// True only if `path` is a DIRECT child of `root` once symlinks and ".." are
// resolved. The root itself, its parents, siblings and unresolvable paths are
// all refused: every recursive delete of a backup goes through this.
bool directChildOf(const std::string& root, const std::string& path) {
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path r = fs::weakly_canonical(root, ec);
    if (ec || r.empty()) return false;
    fs::path p = fs::weakly_canonical(path, ec);
    if (ec || p.empty() || p == r) return false;
    return p.parent_path() == r;
}

// Column names of a (fixed, code-chosen) table, so a restore can only ever
// write columns that really exist — a tampered data.json can't smuggle SQL
// through a key name.
std::set<std::string> tableColumns(sqlite3* h, const char* table) {
    std::set<std::string> cols;
    Stmt q(h, (std::string("PRAGMA table_info(") + table + ")").c_str());
    while (q.step()) cols.insert(q.colText(1));
    return cols;
}

// Shared guards for remove + wipe. Fills `r` and returns false to refuse.
bool lifecycleGuards(sqlite3* h, int64_t targetId, int64_t byAdminId, std::string& email,
                     std::string& displayName, std::string& status, CloudDB::LifecycleResult& r) {
    std::string role;
    {
        Stmt q(h, "SELECT email, display_name, role, status FROM users WHERE id = ?");
        q.bind(1, targetId);
        if (!q.step()) { r.status = 404; r.error = "user not found"; return false; }
        email = q.colText(0); displayName = q.colText(1); role = q.colText(2); status = q.colText(3);
    }
    if (targetId == byAdminId) {
        r.status = 409; r.error = "cannot remove or wipe your own account"; return false;
    }
    // Only an ACTIVE admin counts: removing one who is already suspended/removed
    // can't leave the system without an admin who can act.
    if (role == "admin" && status == "active") {
        Stmt q(h, "SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'");
        if (!q.step() || q.colInt64(0) <= 1) {
            r.status = 409; r.error = "cannot remove the last admin"; return false;
        }
    }
    return true;
}

RemovedUser readRemoved(Stmt& q) {
    RemovedUser u;
    u.id = q.colInt64(0);
    u.original_user_id = q.colInt64(1);
    u.email = q.colText(2);
    u.display_name = q.colText(3);
    u.backup_path = q.colText(4);
    u.removed_at = q.colText(5);
    u.removed_by = q.colInt64(6);
    u.reason = q.colText(7);
    return u;
}

const char* kRemovedCols = "id, original_user_id, email, display_name, backup_path, removed_at, removed_by, reason";

} // namespace

CloudDB::LifecycleResult CloudDB::removeUser(
        int64_t targetId, int64_t byAdminId, const std::string& backupRoot, const std::string& reason,
        const std::function<bool(const std::string&)>& stageBlobs) {
    namespace fs = std::filesystem;
    LifecycleResult r;
    std::unique_lock lock(db_mutex_);
    std::string backupDir;
    bool backupCreated = false;
    auto fail = [&](const std::string& msg) {
        if (backupCreated) { std::error_code ec; fs::remove_all(backupDir, ec); backupCreated = false; }
        r.ok = false; r.status = 500; r.error = msg;
        return r;
    };
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        std::string email, displayName, status;
        if (!lifecycleGuards(c.h, targetId, byAdminId, email, displayName, status, r)) return r;
        if (status == "removed") { r.status = 409; r.error = "account is already removed"; return r; }

        // 1. Snapshot the account's data rows (files/folders stay ciphertext;
        //    notes are ciphertext too now, except an un-upgraded legacy note).
        std::time_t now = std::time(nullptr);
        std::tm tm{}; gmtime_r(&now, &tm);
        char stamp[32], iso[32];
        std::strftime(stamp, sizeof stamp, "%Y%m%dT%H%M%SZ", &tm);
        std::strftime(iso, sizeof iso, "%Y-%m-%dT%H:%M:%SZ", &tm);

        json snap = {{"version", 1}, {"removedAt", iso}, {"removedBy", byAdminId}};
        snap["user"]    = dumpRows(c.h, "SELECT * FROM users WHERE id = ?", targetId).at(0);
        snap["folders"] = dumpRows(c.h, "SELECT * FROM folders WHERE user_id = ?", targetId);
        snap["files"]   = dumpRows(c.h, "SELECT * FROM files WHERE user_id = ?", targetId);
        snap["notes"]   = dumpRows(c.h, "SELECT * FROM notes WHERE user_id = ?", targetId);

        // 2. Write the bundle (dir 0700, files 0600). create_directory returning
        //    false means the target already existed: never write into it.
        std::error_code ec;
        fs::create_directories(backupRoot, ec);
        if (ec) return fail("could not create backup root: " + ec.message());
        ::chmod(backupRoot.c_str(), S_IRWXU);
        backupDir = fs::absolute(fs::path(backupRoot) / (std::to_string(targetId) + "_" + stamp)).string();
        if (!fs::create_directory(backupDir, ec) || ec) return fail("could not create backup directory");
        backupCreated = true;
        ::chmod(backupDir.c_str(), S_IRWXU);

        const std::string dataPath = backupDir + "/data.json";
        {
            std::ofstream f(dataPath, std::ios::binary | std::ios::trunc);
            // 'replace': a legacy plaintext filename with invalid UTF-8 must not
            // make an account impossible to remove (blobs are copied byte-exact).
            f << snap.dump(2, ' ', false, json::error_handler_t::replace);
            f.flush();
            if (!f) return fail("could not write backup data");
        }
        ::chmod(dataPath.c_str(), 0600);
        if (fs::file_size(dataPath, ec) == 0 || ec) return fail("backup data is empty");

        if (!stageBlobs(backupDir + "/storage")) return fail("could not back up stored files");

        // 3. Only now touch live data, all in ONE transaction: record the
        //    removal, mark the account removed, and clear its data + sessions.
        //    The account row (credentials, E2E key material) and API keys stay.
        if (!execOk(c.h, "BEGIN IMMEDIATE")) return fail("could not start transaction");
        bool ok = false;
        do {
            {
                Stmt ins(c.h, "INSERT INTO removed_users(original_user_id, email, display_name, backup_path, removed_by, reason) "
                              "VALUES(?, ?, ?, ?, ?, ?)");
                ins.bind(1, targetId); ins.bind(2, email); ins.bind(3, displayName);
                ins.bind(4, backupDir); ins.bind(5, byAdminId); ins.bind(6, reason);
                if (sqlite3_step(ins.s) != SQLITE_DONE) break;
            }
            if (!execBound(c.h, "UPDATE users SET status = 'removed' WHERE id = ? AND status != 'removed'", targetId, true)) break;
            if (!execBound(c.h, "DELETE FROM folders WHERE user_id = ?", targetId)) break;
            if (!execBound(c.h, "DELETE FROM files WHERE user_id = ?", targetId)) break;
            if (!execBound(c.h, "DELETE FROM notes WHERE user_id = ?", targetId)) break;
            if (!execBound(c.h, "DELETE FROM upload_sessions WHERE user_id = ?", targetId)) break;
            if (!execBound(c.h, "DELETE FROM sessions WHERE user_id = ?", targetId)) break;
            ok = true;
        } while (false);
        if (!ok || !execOk(c.h, "COMMIT")) {
            execOk(c.h, "ROLLBACK");
            return fail("could not remove account data; nothing was changed");
        }
        r.ok = true; r.status = 200;
        return r;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("removeUser: " + std::string(e.what()));
        return fail("could not remove account data; nothing was changed");
    }
}

CloudDB::LifecycleResult CloudDB::restoreUser(
        int64_t targetId, const std::string& backupRoot,
        const std::function<bool(const std::string&, const std::vector<std::string>&)>& restoreBlobs,
        const std::function<void(const std::vector<std::string>&)>& undoBlobs) {
    namespace fs = std::filesystem;
    LifecycleResult r;
    std::unique_lock lock(db_mutex_);
    std::vector<std::string> placedKeys;
    bool blobsPlaced = false;
    auto fail = [&](int code, const std::string& msg) {
        if (blobsPlaced) { undoBlobs(placedKeys); blobsPlaced = false; }
        r.ok = false; r.status = code; r.error = msg;
        return r;
    };
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        std::string status;
        {
            Stmt q(c.h, "SELECT status FROM users WHERE id = ?");
            q.bind(1, targetId);
            if (!q.step()) return fail(404, "user not found");
            status = q.colText(0);
        }
        if (status != "removed") return fail(409, "account is not removed");

        std::string backupDir;
        {
            Stmt q(c.h, "SELECT backup_path FROM removed_users WHERE original_user_id = ?");
            q.bind(1, targetId);
            if (!q.step()) return fail(409, "no backup record for this account");
            backupDir = q.colText(0);
        }
        // Defense in depth: never read (or later delete) outside the backup root.
        if (!directChildOf(backupRoot, backupDir)) {
            utils::Logger::get_instance().error("restoreUser: backup path outside backup root: " + backupDir);
            return fail(500, "backup path is outside the backup directory; refusing to use it");
        }

        // Read + validate the snapshot before touching anything.
        const std::string dataPath = backupDir + "/data.json";
        std::error_code ec;
        auto sz = fs::file_size(dataPath, ec);
        if (ec) return fail(500, "backup data.json is missing");
        if (sz > (1ull << 30)) return fail(500, "backup data.json is unreasonably large");
        json snap;
        {
            std::ifstream f(dataPath, std::ios::binary);
            snap = json::parse(f, nullptr, false);
        }
        if (snap.is_discarded() || !snap.is_object() || snap.value("version", 0) != 1 ||
            !snap.contains("user") || !snap["user"].is_object() ||
            !snap["user"].contains("id") || !snap["user"]["id"].is_number_integer() ||
            !snap.contains("folders") || !snap["folders"].is_array() ||
            !snap.contains("files") || !snap["files"].is_array() ||
            !snap.contains("notes") || !snap["notes"].is_array())
            return fail(500, "backup data.json is not a valid backup");
        if (snap["user"]["id"].get<int64_t>() != targetId)
            return fail(409, "this backup belongs to a different account");

        // Every file row must have its blob in the bundle (else the backup is
        // incomplete and we would restore rows pointing at nothing).
        std::set<std::string> keySet;
        for (const auto& row : snap["files"]) {
            if (!row.is_object() || !row.contains("storage_key") || !row["storage_key"].is_string())
                return fail(500, "backup contains a malformed file record");
            const std::string key = row["storage_key"].get<std::string>();
            if (!safeBlobKey(key)) return fail(500, "backup contains an unsafe storage key");
            if (!fs::is_regular_file(fs::path(backupDir) / "storage" / key, ec))
                return fail(500, "backup is incomplete: a stored file is missing from it");
            keySet.insert(key);
        }
        std::vector<std::string> keys(keySet.begin(), keySet.end());

        // Blobs go back FIRST: a row must never point at a missing blob.
        if (!restoreBlobs(backupDir + "/storage", keys))
            return fail(500, "could not restore stored files; nothing was changed");
        placedKeys = keys; blobsPlaced = true;

        if (!execOk(c.h, "BEGIN IMMEDIATE")) return fail(500, "could not start transaction");
        bool ok = false;
        do {
            // Same ids as before, so the folder tree and every reference is
            // identical. Only columns that exist in the live table are written.
            auto insertAll = [&](const char* table, const json& rows, int64_t& counter) -> bool {
                const std::set<std::string> live = tableColumns(c.h, table);
                for (const auto& row : rows) {
                    if (!row.is_object()) return false;
                    if (!row.contains("user_id") || !row["user_id"].is_number_integer() ||
                        row["user_id"].get<int64_t>() != targetId) return false;
                    std::vector<std::string> cols;
                    for (auto it = row.begin(); it != row.end(); ++it)
                        if (live.count(it.key())) cols.push_back(it.key());
                    if (cols.empty()) return false;
                    std::string sql = std::string("INSERT INTO ") + table + "(";
                    for (size_t i = 0; i < cols.size(); ++i) sql += (i ? "," : "") + cols[i];
                    sql += ") VALUES(";
                    for (size_t i = 0; i < cols.size(); ++i) sql += (i ? ",?" : "?");
                    sql += ")";
                    Stmt ins(c.h, sql.c_str());
                    for (size_t i = 0; i < cols.size(); ++i) {
                        const json& v = row[cols[i]];
                        const int idx = static_cast<int>(i) + 1;
                        if (v.is_number_integer())    sqlite3_bind_int64(ins.s, idx, v.get<int64_t>());
                        else if (v.is_number_float()) sqlite3_bind_double(ins.s, idx, v.get<double>());
                        else if (v.is_string())       ins.bind(idx, v.get<std::string>());
                        else if (v.is_null())         ins.bindNull(idx);
                        else return false;
                    }
                    if (sqlite3_step(ins.s) != SQLITE_DONE) return false;
                    ++counter;
                }
                return true;
            };
            if (!insertAll("folders", snap["folders"], r.nFolders)) break;
            if (!insertAll("files",   snap["files"],   r.nFiles))   break;
            if (!insertAll("notes",   snap["notes"],   r.nNotes))   break;
            if (!execBound(c.h, "UPDATE users SET status = 'active' WHERE id = ? AND status = 'removed'", targetId, true)) break;
            if (!execBound(c.h, "DELETE FROM removed_users WHERE original_user_id = ?", targetId, true)) break;
            ok = true;
        } while (false);
        if (!ok || !execOk(c.h, "COMMIT")) {
            execOk(c.h, "ROLLBACK");
            r.nFolders = r.nFiles = r.nNotes = 0;
            return fail(500, "could not restore the account; nothing was changed");
        }
        blobsPlaced = false;   // committed: the blobs are the account's again

        // The backup has been consumed. If deleting it fails we only leak a
        // directory (there is no record pointing at it any more); say so loudly.
        fs::remove_all(backupDir, ec);
        if (ec) utils::Logger::get_instance().warn("restoreUser: restored, but could not delete the backup " +
                                                   backupDir + ": " + ec.message());
        r.ok = true; r.status = 200;
        return r;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("restoreUser: " + std::string(e.what()));
        r.nFolders = r.nFiles = r.nNotes = 0;
        return fail(500, "could not restore the account; nothing was changed");
    }
}

CloudDB::LifecycleResult CloudDB::wipeUser(int64_t targetId, int64_t byAdminId, const std::string& backupRoot) {
    namespace fs = std::filesystem;
    LifecycleResult r;
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        std::string email, displayName, status;
        if (!lifecycleGuards(c.h, targetId, byAdminId, email, displayName, status, r)) return r;

        // A removed account also has a backup to delete. Vet its path BEFORE the
        // DB transaction, so a tampered record refuses the whole wipe instead of
        // deleting the account and then declining to clean up (or worse).
        std::string backupDir;
        if (status == "removed") {
            Stmt q(c.h, "SELECT backup_path FROM removed_users WHERE original_user_id = ?");
            q.bind(1, targetId);
            if (q.step()) backupDir = q.colText(0);
            if (!backupDir.empty() && !directChildOf(backupRoot, backupDir)) {
                utils::Logger::get_instance().error("wipeUser: refusing backup path outside backup root: " + backupDir);
                r.error = "backup path is outside the backup directory; refusing to delete";
                return r;
            }
        }

        if (!execOk(c.h, "BEGIN IMMEDIATE")) { r.error = "could not start transaction"; return r; }
        bool ok = execBound(c.h, "DELETE FROM removed_users WHERE original_user_id = ?", targetId) &&
                  execBound(c.h, "DELETE FROM users WHERE id = ?", targetId, true);
        if (!ok || !execOk(c.h, "COMMIT")) {
            execOk(c.h, "ROLLBACK");
            r.error = "could not wipe account; nothing was changed";
            return r;
        }
        r.ok = true; r.status = 200;
        if (!backupDir.empty()) {
            std::error_code ec;
            fs::remove_all(backupDir, ec);
            r.backupRemoved = !ec;
            if (ec) utils::Logger::get_instance().warn("wipeUser: account wiped but backup " + backupDir +
                                                       " could not be deleted: " + ec.message());
        }
        return r;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("wipeUser: " + std::string(e.what()));
        r.error = "could not wipe account; nothing was changed";
        return r;
    }
}

std::vector<RemovedUser> CloudDB::listRemovedUsers() {
    std::shared_lock lock(db_mutex_);
    std::vector<RemovedUser> out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, (std::string("SELECT ") + kRemovedCols + " FROM removed_users ORDER BY id DESC").c_str());
        while (q.step()) out.push_back(readRemoved(q));
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("listRemovedUsers: " + std::string(e.what()));
    }
    return out;
}

std::optional<RemovedUser> CloudDB::getRemovalFor(int64_t userId) {
    std::shared_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, (std::string("SELECT ") + kRemovedCols + " FROM removed_users WHERE original_user_id = ?").c_str());
        q.bind(1, userId);
        if (!q.step()) return std::nullopt;
        return readRemoved(q);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("getRemovalFor: " + std::string(e.what()));
        return std::nullopt;
    }
}
