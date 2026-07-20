#pragma once

#include "db/models.h"
#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <shared_mutex>

// CloudDB — the multi-user data layer for the cloud suite.
//
// Adapted from project-tracker's ProjectDB: same discipline — every query is
// parameterized, reads take a shared lock, writes take an exclusive lock. The
// domain is generalized from projects to users / api keys / sessions / files.
//
// File *blobs* live on disk (see FileStore); only metadata lives here, which
// keeps the DB small and suits large media.
class CloudDB {
public:
    explicit CloudDB(const std::string& dbPath);

    // ---- Users (auth) ----
    // Returns the new user's id, or -1 on failure (e.g. email already taken).
    int64_t createUser(const std::string& email,
                       const std::string& displayName,
                       const std::string& passwordHash);
    std::optional<User> findUserByEmail(const std::string& email);
    std::optional<User> findUserById(int64_t id);

    // ---- Sessions ----
    // Stores only the hash of the token; expiresAt is a unix epoch (seconds).
    bool createSession(int64_t userId, const std::string& tokenHash,
                       const std::string& clientIp, int64_t expiresAt);
    // Returns the owning user id if the session hash is valid and unexpired.
    std::optional<int64_t> userForSession(const std::string& tokenHash);
    void deleteSession(const std::string& tokenHash);
    int  purgeExpiredSessions();  // returns rows removed

    // ---- API keys ----
    // Stores only the hash of the key. Returns new key id or -1.
    int64_t createApiKey(int64_t userId, const std::string& name,
                         const std::string& prefix, const std::string& keyHash);
    // Returns owning user id if the key hash exists; also bumps last_used_at.
    std::optional<int64_t> userForApiKey(const std::string& keyHash);
    std::vector<ApiKeyInfo> listApiKeys(int64_t userId);
    bool revokeApiKey(int64_t userId, int64_t keyId);

    // ---- Folders (per-user tree; parentId/folderId 0 = root) ----
    int64_t createFolder(int64_t userId, int64_t parentId, const std::string& name);
    std::vector<Folder> listFolders(int64_t userId, int64_t parentId);
    std::optional<Folder> getFolder(int64_t userId, int64_t folderId);
    bool renameFolder(int64_t userId, int64_t folderId, const std::string& name);
    bool moveFolder(int64_t userId, int64_t folderId, int64_t newParentId); // cycle-safe
    // Recursively deletes a folder and everything under it; fills storageKeys
    // with the blob keys to unlink from disk.
    bool deleteFolderRecursive(int64_t userId, int64_t folderId,
                               std::vector<std::string>& storageKeys);
    // Ancestors of a folder, root-first (for breadcrumbs). Empty for root.
    std::vector<Folder> folderPath(int64_t userId, int64_t folderId);
    // True if folderId exists for the user (or folderId == 0, i.e. root).
    bool folderExists(int64_t userId, int64_t folderId);

    // ---- Files (metadata; blobs handled by FileStore) ----
    int64_t addFile(int64_t userId, int64_t folderId, const std::string& name,
                    const std::string& mime, int64_t size, const std::string& storageKey);
    std::vector<FileMeta> listFiles(int64_t userId, int64_t folderId);
    std::optional<FileMeta> getFile(int64_t userId, int64_t fileId);
    bool moveFile(int64_t userId, int64_t fileId, int64_t folderId);
    bool renameFile(int64_t userId, int64_t fileId, const std::string& name);
    bool deleteFile(int64_t userId, int64_t fileId);

    // ---- Chunked uploads ----
    bool createUploadSession(int64_t userId, const std::string& id, int64_t folderId,
                             const std::string& name, const std::string& mime,
                             int64_t size, const std::string& storageKey);
    std::optional<UploadSession> getUploadSession(int64_t userId, const std::string& id);
    bool setUploadReceived(int64_t userId, const std::string& id, int64_t received);
    bool deleteUploadSession(int64_t userId, const std::string& id);

    // ---- Notes ----
    int64_t createNote(int64_t userId, const std::string& title, const std::string& body);
    std::vector<Note> listNotes(int64_t userId);              // summaries (no body)
    std::optional<Note> getNote(int64_t userId, int64_t noteId);
    bool updateNote(int64_t userId, int64_t noteId,
                    const std::string& title, const std::string& body);
    bool deleteNote(int64_t userId, int64_t noteId);

private:
    std::string dbPath_;
    mutable std::shared_mutex db_mutex_;  // reads: shared_lock, writes: unique_lock
};
