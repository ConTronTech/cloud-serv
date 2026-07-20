#include "db/database.h"
#include "utils/logger.h"

#include <sqlite3.h>
#include <ctime>
#include <stdexcept>
#include <string>

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
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                mime TEXT DEFAULT 'application/octet-stream',
                size INTEGER DEFAULT 0,
                storage_key TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_files_user ON files(user_id);
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
                name TEXT NOT NULL,
                mime TEXT DEFAULT 'application/octet-stream',
                size INTEGER DEFAULT 0,
                received INTEGER DEFAULT 0,
                storage_key TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_uploads_user ON upload_sessions(user_id);
        )";
        char* err = nullptr;
        if (sqlite3_exec(c.h, schema, nullptr, nullptr, &err) != SQLITE_OK) {
            std::string msg = err ? err : "schema exec failed";
            sqlite3_free(err);
            throw std::runtime_error(msg);
        }
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
        Stmt q(c.h, "SELECT id, email, display_name, password_hash, created_at "
                    "FROM users WHERE email = ?");
        q.bind(1, email);
        if (!q.step()) return std::nullopt;
        User u;
        u.id = q.colInt64(0);
        u.email = q.colText(1);
        u.display_name = q.colText(2);
        u.password_hash = q.colText(3);
        u.created_at = q.colText(4);
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
        Stmt q(c.h, "SELECT id, email, display_name, password_hash, created_at "
                    "FROM users WHERE id = ?");
        q.bind(1, id);
        if (!q.step()) return std::nullopt;
        User u;
        u.id = q.colInt64(0);
        u.email = q.colText(1);
        u.display_name = q.colText(2);
        u.password_hash = q.colText(3);
        u.created_at = q.colText(4);
        return u;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("findUserById: " + std::string(e.what()));
        return std::nullopt;
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

int64_t CloudDB::addFile(int64_t userId, const std::string& name, const std::string& mime,
                         int64_t size, const std::string& storageKey) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "INSERT INTO files(user_id, name, mime, size, storage_key) "
                    "VALUES(?, ?, ?, ?, ?)");
        q.bind(1, userId);
        q.bind(2, name);
        q.bind(3, mime);
        q.bind(4, size);
        q.bind(5, storageKey);
        if (sqlite3_step(q.s) != SQLITE_DONE) return -1;
        return sqlite3_last_insert_rowid(c.h);
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("addFile: " + std::string(e.what()));
        return -1;
    }
}

std::vector<FileMeta> CloudDB::listFiles(int64_t userId) {
    std::shared_lock lock(db_mutex_);
    std::vector<FileMeta> out;
    try {
        Conn c(dbPath_, SQLITE_OPEN_READONLY);
        Stmt q(c.h, "SELECT id, user_id, name, mime, size, storage_key, created_at "
                    "FROM files WHERE user_id = ? ORDER BY created_at DESC");
        q.bind(1, userId);
        while (q.step()) {
            FileMeta f;
            f.id = q.colInt64(0);
            f.user_id = q.colInt64(1);
            f.name = q.colText(2);
            f.mime = q.colText(3);
            f.size = q.colInt64(4);
            f.storage_key = q.colText(5);
            f.created_at = q.colText(6);
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
        Stmt q(c.h, "SELECT id, user_id, name, mime, size, storage_key, created_at "
                    "FROM files WHERE id = ? AND user_id = ?");
        q.bind(1, fileId);
        q.bind(2, userId);
        if (!q.step()) return std::nullopt;
        FileMeta f;
        f.id = q.colInt64(0);
        f.user_id = q.colInt64(1);
        f.name = q.colText(2);
        f.mime = q.colText(3);
        f.size = q.colInt64(4);
        f.storage_key = q.colText(5);
        f.created_at = q.colText(6);
        return f;
    } catch (const std::exception& e) {
        utils::Logger::get_instance().error("getFile: " + std::string(e.what()));
        return std::nullopt;
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

// ==== Chunked uploads ====

bool CloudDB::createUploadSession(int64_t userId, const std::string& id, const std::string& name,
                                  const std::string& mime, int64_t size, const std::string& storageKey) {
    std::unique_lock lock(db_mutex_);
    try {
        Conn c(dbPath_, SQLITE_OPEN_READWRITE);
        Stmt q(c.h, "INSERT INTO upload_sessions(id, user_id, name, mime, size, received, storage_key) "
                    "VALUES(?, ?, ?, ?, ?, 0, ?)");
        q.bind(1, id);
        q.bind(2, userId);
        q.bind(3, name);
        q.bind(4, mime);
        q.bind(5, size);
        q.bind(6, storageKey);
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
        Stmt q(c.h, "SELECT id, user_id, name, mime, size, received, storage_key, created_at "
                    "FROM upload_sessions WHERE id = ? AND user_id = ?");
        q.bind(1, id);
        q.bind(2, userId);
        if (!q.step()) return std::nullopt;
        UploadSession u;
        u.id = q.colText(0);
        u.user_id = q.colInt64(1);
        u.name = q.colText(2);
        u.mime = q.colText(3);
        u.size = q.colInt64(4);
        u.received = q.colInt64(5);
        u.storage_key = q.colText(6);
        u.created_at = q.colText(7);
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
