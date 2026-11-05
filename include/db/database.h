#pragma once

#include "db/models.h"
#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <utility>
#include <shared_mutex>
#include <functional>

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
    // E2E: store the client-generated key material for a user.
    bool setUserKeys(int64_t userId, const std::string& kdfSalt,
                     const std::string& wrappedDek, const std::string& wrappedDekRecovery);
    // The KDF salt for an email (for the pre-login derivation). nullopt if unknown.
    std::optional<std::string> saltForEmail(const std::string& email);
    // A stable, random, server-side secret (generated once, persisted). Used to
    // key derivations that must not be client-computable, e.g. the decoy salt.
    std::string serverSecret();

    // ---- External identities (Sign in with authentik / OIDC) ----
    struct Identity { int64_t id = 0; int64_t user_id = 0; std::string issuer, subject, email, created_at; };
    std::optional<int64_t> userForIdentity(const std::string& issuer, const std::string& subject);
    // false if that identity is already linked to an account
    bool linkIdentity(int64_t userId, const std::string& issuer, const std::string& subject, const std::string& email);
    std::vector<Identity> listIdentities(int64_t userId);
    bool unlinkIdentity(int64_t userId, int64_t identityId);
    // Accounts created through SSO have no password the user knows: local_login = 0.
    bool setLocalLogin(int64_t userId, bool on);
    bool hasLocalLogin(int64_t userId);

    // ---- Sessions ----
    // Stores only the hash of the token; expiresAt is a unix epoch (seconds).
    bool createSession(int64_t userId, const std::string& tokenHash,
                       const std::string& clientIp, int64_t expiresAt);
    // Returns the owning user id if the session hash is valid and unexpired.
    std::optional<int64_t> userForSession(const std::string& tokenHash);
    void deleteSession(const std::string& tokenHash);
    // Sign out every other device of this user (keeps the session with keepTokenHash).
    int deleteOtherSessions(int64_t userId, const std::string& keepTokenHash);
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
    int64_t createFolder(int64_t userId, int64_t parentId, const std::string& name,
                         const std::string& encName = "");
    std::vector<Folder> listFolders(int64_t userId, int64_t parentId);
    std::optional<Folder> getFolder(int64_t userId, int64_t folderId);
    bool renameFolder(int64_t userId, int64_t folderId, const std::string& name,
                      const std::string& encName = "");
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
                    const std::string& mime, int64_t size, const std::string& storageKey,
                    const std::string& wrappedKey = "", const std::string& encName = "",
                    const std::string& encMime = "");
    std::vector<FileMeta> listFiles(int64_t userId, int64_t folderId);
    std::optional<FileMeta> getFile(int64_t userId, int64_t fileId);
    bool moveFile(int64_t userId, int64_t fileId, int64_t folderId);
    bool renameFile(int64_t userId, int64_t fileId, const std::string& name,
                    const std::string& encName = "");
    bool deleteFile(int64_t userId, int64_t fileId);

    // ---- Aggregates / search ----
    // Total bytes used and file count for a user.
    std::pair<int64_t, int64_t> usage(int64_t userId);
    // Search files across all folders. q = case-insensitive name substring
    // (empty = any). category = image|video|audio|document|other|"" (any).
    std::vector<FileMeta> searchFiles(int64_t userId, const std::string& q,
                                      const std::string& category, int limit);
    // Search folders by name substring across the whole tree.
    std::vector<Folder> searchFolders(int64_t userId, const std::string& q, int limit);

    // ---- Starred / recent ----
    bool setFileStarred(int64_t userId, int64_t fileId, bool starred);
    bool setFolderStarred(int64_t userId, int64_t folderId, bool starred);
    std::vector<FileMeta> starredFiles(int64_t userId);
    std::vector<Folder> starredFolders(int64_t userId);
    std::vector<FileMeta> recentFiles(int64_t userId, int limit);

    // ---- Chunked uploads ----
    bool createUploadSession(int64_t userId, const std::string& id, int64_t folderId,
                             const std::string& name, const std::string& mime,
                             int64_t size, const std::string& storageKey,
                             const std::string& wrappedKey, int64_t plainSize,
                             const std::string& encName = "", const std::string& encMime = "");
    std::optional<UploadSession> getUploadSession(int64_t userId, const std::string& id);
    bool setUploadReceived(int64_t userId, const std::string& id, int64_t received);
    bool deleteUploadSession(int64_t userId, const std::string& id);

    // ---- Notes ----
    int64_t createNote(int64_t userId, const std::string& title, const std::string& body,
                       const std::string& encTitle = "", const std::string& encBody = "");
    std::vector<Note> listNotes(int64_t userId);              // summaries (no body)
    std::optional<Note> getNote(int64_t userId, int64_t noteId);
    // preserveUpdatedAt: keep the note's timestamp (used when a client silently
    // re-encrypts a legacy plaintext note, so migration doesn't reorder the list).
    bool updateNote(int64_t userId, int64_t noteId,
                    const std::string& title, const std::string& body,
                    const std::string& encTitle = "", const std::string& encBody = "",
                    bool preserveUpdatedAt = false);
    bool deleteNote(int64_t userId, int64_t noteId);

    // ---- Administration ----
    // Every user, newest-first. Admin-only at the route layer; never returns
    // anything E2E (names/contents) — only the same account/aggregate fields
    // toAdminJson() exposes.
    std::vector<User> listAllUsers();
    bool setUserRole(int64_t userId, const std::string& role);       // "user" | "admin"
    bool setUserSuspended(int64_t userId, bool suspended);
    bool setUserQuota(int64_t userId, std::optional<int64_t> quotaBytes); // nullopt = unlimited
    // Per-account "encrypt my files" preference. nullopt = never set (use FILES_ENCRYPT_DEFAULT).
    std::optional<bool> getEncryptFiles(int64_t userId);
    bool setDisplayName(int64_t userId, const std::string& name);
    // Password change: new auth hash + new KDF salt + DEK re-wrapped under the new password.
    // The recovery-key wrap is untouched (it wraps the same DEK, so it stays valid).
    bool setPasswordAndKeys(int64_t userId, const std::string& pwHash,
                            const std::string& kdfSalt, const std::string& wrappedDek);
    bool setEncryptFiles(int64_t userId, bool on);
    // Admins who can actually act: role admin AND status active. A suspended or
    // removed admin does not count, so "last admin" guards can't be satisfied by
    // an account that is locked out.
    int  countAdmins();
    // True if adding `additionalBytes` keeps the user within their quota
    // (always true when they have no quota set, i.e. unlimited).
    bool hasQuotaRoom(int64_t userId, int64_t additionalBytes);

    // ---- Account lifecycle (admin remove / restore / wipe) ----
    // `status` is the HTTP status the route should answer with on failure.
    struct LifecycleResult {
        bool ok = false;
        int status = 500;
        std::string error;
        int64_t nFolders = 0, nFiles = 0, nNotes = 0;  // restoreUser only
        bool backupRemoved = false;                    // wipeUser (removed account) only
    };
    // "Backup + temp remove". The ACCOUNT STAYS (status -> 'removed'; password,
    // recovery key and E2E key material untouched) so its owner can sign in and
    // see a notice; only its data goes. Under ONE exclusive lock (nothing can
    // slip in between the snapshot and the delete): snapshot folders/files/notes
    // to <backupRoot>/<id>_<utc>/data.json, let `stageBlobs` populate
    // <that>/storage (the route passes FileStore::stageUserDir), verify, then in
    // a single transaction record the removal, mark the user removed, delete
    // their folders/files/notes/upload-sessions and drop their sessions. Any
    // failure rolls the transaction back and deletes the partial backup, leaving
    // the live account untouched. The caller deletes the live blob dir after.
    // Refuses: unknown user, yourself, an already-removed account, the last
    // active admin.
    LifecycleResult removeUser(int64_t targetId, int64_t byAdminId, const std::string& backupRoot,
                               const std::string& reason,
                               const std::function<bool(const std::string& destStorageDir)>& stageBlobs);
    // Bring a removed account's data back exactly as it was (same ids, so the
    // folder tree and every reference is identical), then delete the backup.
    // `restoreBlobs(srcStorageDir, keys)` must put every listed blob into the
    // live store or clean up after itself and return false; `undoBlobs(keys)`
    // removes them again if the DB step fails afterwards. Blobs are placed
    // BEFORE the rows so a row never points at a missing blob. Refuses an
    // account that isn't removed, a backup that is incomplete, belongs to
    // another account, or lies outside backupRoot.
    LifecycleResult restoreUser(int64_t targetId, const std::string& backupRoot,
                                const std::function<bool(const std::string&, const std::vector<std::string>&)>& restoreBlobs,
                                const std::function<void(const std::vector<std::string>&)>& undoBlobs);
    // Permanent: delete the account and all its rows in one transaction, no
    // backup. For an already-removed account this also deletes its backup
    // bundle (only ever a direct child of backupRoot). The caller deletes the
    // live blob dir afterwards. Refuses: unknown user, yourself, the last
    // active admin.
    LifecycleResult wipeUser(int64_t targetId, int64_t byAdminId, const std::string& backupRoot);

    std::vector<RemovedUser> listRemovedUsers();
    // The removal record for a user, if that account is currently removed.
    std::optional<RemovedUser> getRemovalFor(int64_t userId);

private:
    std::string dbPath_;
    mutable std::shared_mutex db_mutex_;  // reads: shared_lock, writes: unique_lock
};
