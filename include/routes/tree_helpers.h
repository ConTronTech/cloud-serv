#pragma once

// Shared bits for routes that serve real-folder ("tree") accounts. See docs/REAL_FOLDERS.md.

#include "db/database.h"
#include "http/middleware.h"
#include "storage/tree_store.h"

#include <cerrno>
#include <optional>
#include <string>

namespace routes::tree {

// The account's dir when it uses real folders, else nullopt (blob storage).
inline std::optional<std::string> account(CloudDB& db, const TreeStore& t, int64_t userId) {
    if (!t.enabled()) return std::nullopt;
    return db.treeDir(userId);
}

// Folder id -> path components below the account root. nullopt if the chain is broken.
inline std::optional<TreeStore::Rel> folderRel(CloudDB& db, int64_t userId, int64_t folderId) {
    TreeStore::Rel rel;
    if (folderId == 0) return rel;
    auto chain = db.folderPath(userId, folderId);
    if (chain.empty() || chain.back().id != folderId || chain.front().parent_id != 0) return std::nullopt;
    for (const auto& f : chain) rel.push_back(f.name);
    return rel;
}

// errno from a TreeStore call -> HTTP error.
inline crow::response fail(int e) {
    switch (e) {
        case EEXIST: case ENOTEMPTY: return http::jsonError(409, "a file or folder with that name already exists");
        case ENOENT:  return http::jsonError(404, "not found on disk (it may have been moved outside the app; a rescan will catch up)");
        case EINVAL:  return http::jsonError(400, "invalid name or move");
        case ENOTDIR: return http::jsonError(409, "path is not a folder");
        case ENOSPC: case EDQUOT: return http::jsonError(507, "the storage drive is full");
        case EACCES: case EPERM: case EROFS: return http::jsonError(500, "storage is not writable");
        default:      return http::jsonError(500, "storage error");
    }
}

inline crow::response noEncryption() {
    return http::jsonError(400, "end-to-end encryption is not available for real-folder accounts");
}

} // namespace routes::tree
