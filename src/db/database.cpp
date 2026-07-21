#include "db/database.h"
#include "utils/logger.h"
#include "security/crypto.h"

#include <sqlite3.h>
#include <ctime>
#include <stdexcept>
#include <string>
#include <algorithm>

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

    bool step() { return sqlite3_step(s) == SQLITE_ROW; }
    void exec() { sqlite3_step(s); }

    int64_t colInt64(int i) { return sqlite3_column_int64(s, i); }
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
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_uploads_user ON upload_sessions(user_id);
            CREATE TABLE IF NOT EXISTS app_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
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
        return sqlite3_last_insert_rowid(c.h);
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
                    "kdf_salt, wrapped_dek, wrapped_dek_recovery "
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
                    "kdf_salt, wrapped_dek, wrapped_dek_recovery "
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
        Stmt q(c.h, "SELECT user_id, expires_at FROM sessions WHERE token_hash = ?");
        q.bind(1, tokenHash);
        if (!q.step()) return std::nullopt;
        int64_t userId = q.colInt64(0);
        int64_t expiresAt = q.colInt64(1);
        if (expiresAt < nowEpoch()) return std::nullopt;  // expired
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
            Stmt q(c.h, "SELECT id, user_id FROM api_keys WHERE key_hash = ?");
            q.bind(1, keyHash);
            if (!q.step()) return std::nullopt;
            keyId = q.colInt64(0);
            userId = q.colInt64(1);
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
                         const std::string& wrappedKey, const std::string& encName) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "INSERT INTO files(user_id, folder_id, name, mime, size, storage_key, wrapped_key, enc_name) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?)");
        q.bind(1, userId);
        q.bind(2, folderId);
        q.bind(3, name);
        q.bind(4, mime);
        q.bind(5, size);
        q.bind(6, storageKey);
        q.bind(7, wrappedKey);
        q.bind(8, encName);
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
        Stmt q(c.h, "SELECT id, user_id, folder_id, name, mime, size, storage_key, created_at, starred, wrapped_key, enc_name "
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
            f.starred = q.colInt64(8) != 0; f.wrapped_key = q.colText(9); f.enc_name = q.colText(10);
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
        Stmt q(c.h, "SELECT id, user_id, folder_id, name, mime, size, storage_key, created_at, starred, wrapped_key, enc_name "
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
        f.starred = q.colInt64(8) != 0; f.wrapped_key = q.colText(9); f.enc_name = q.colText(10);
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
        Stmt q(c.h, "SELECT COALESCE(SUM(size), 0), COUNT(*) FROM files WHERE user_id = ?");
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
            "SELECT id, user_id, folder_id, name, mime, size, storage_key, created_at, starred, wrapped_key, enc_name "
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
            f.starred = st.colInt64(8) != 0; f.wrapped_key = st.colText(9); f.enc_name = st.colText(10);
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
        Stmt q(c.h, "SELECT id, user_id, folder_id, name, mime, size, storage_key, created_at, starred, wrapped_key, enc_name "
                    "FROM files WHERE user_id = ? AND starred = 1 ORDER BY name COLLATE NOCASE");
        q.bind(1, userId);
        while (q.step()) {
            FileMeta f;
            f.id = q.colInt64(0); f.user_id = q.colInt64(1); f.folder_id = q.colInt64(2);
            f.name = q.colText(3); f.mime = q.colText(4); f.size = q.colInt64(5);
            f.storage_key = q.colText(6); f.created_at = q.colText(7); f.starred = q.colInt64(8) != 0; f.wrapped_key = q.colText(9); f.enc_name = q.colText(10);
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
        Stmt q(c.h, "SELECT id, user_id, folder_id, name, mime, size, storage_key, created_at, starred, wrapped_key, enc_name "
                    "FROM files WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT ?");
        q.bind(1, userId);
        q.bind(2, static_cast<int64_t>(limit > 0 ? limit : 50));
        while (q.step()) {
            FileMeta f;
            f.id = q.colInt64(0); f.user_id = q.colInt64(1); f.folder_id = q.colInt64(2);
            f.name = q.colText(3); f.mime = q.colText(4); f.size = q.colInt64(5);
            f.storage_key = q.colText(6); f.created_at = q.colText(7); f.starred = q.colInt64(8) != 0; f.wrapped_key = q.colText(9); f.enc_name = q.colText(10);
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
                                  const std::string& encName) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "INSERT INTO upload_sessions(id, user_id, folder_id, name, mime, size, received, "
                    "storage_key, wrapped_key, plain_size, enc_name) VALUES(?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)");
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
                    "wrapped_key, plain_size, enc_name FROM upload_sessions WHERE id = ? AND user_id = ?");
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
        Stmt q(c.h, "UPDATE upload_sessions SET received = ? WHERE id = ? AND user_id = ?");
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

int64_t CloudDB::createNote(int64_t userId, const std::string& title, const std::string& body) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "INSERT INTO notes(user_id, title, body) VALUES(?, ?, ?)");
        q.bind(1, userId);
        q.bind(2, title);
        q.bind(3, body);
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
        Stmt q(c.h, "SELECT id, user_id, title, created_at, updated_at "
                    "FROM notes WHERE user_id = ? ORDER BY updated_at DESC");
        q.bind(1, userId);
        while (q.step()) {
            Note n;
            n.id = q.colInt64(0);
            n.user_id = q.colInt64(1);
            n.title = q.colText(2);
            n.created_at = q.colText(3);
            n.updated_at = q.colText(4);
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
        Stmt q(c.h, "SELECT id, user_id, title, body, created_at, updated_at "
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
        return n;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("getNote: " + std::string(e.what()));
        return std::nullopt;
    }
}

bool CloudDB::updateNote(int64_t userId, int64_t noteId,
                         const std::string& title, const std::string& body) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "UPDATE notes SET title = ?, body = ?, updated_at = CURRENT_TIMESTAMP "
                    "WHERE id = ? AND user_id = ?");
        q.bind(1, title);
        q.bind(2, body);
        q.bind(3, noteId);
        q.bind(4, userId);
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
