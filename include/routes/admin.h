#pragma once

#include <crow.h>
#include "http/middleware.h"
#include "db/database.h"
#include "storage/file_store.h"

namespace routes {

// Registers admin-only account-management endpoints. Every route requires a
// login session (never an API key — same rule as /api/auth/api-keys) AND the
// caller's role to be "admin".
//
// These endpoints manage ACCOUNTS ONLY — who can log in, their role, how much
// storage they're allowed, and whether the account exists. None of them can
// read, list, or restore a user's files or folders: contents, names and mime
// types are end-to-end encrypted and the server never has a key, so there is no
// route to build. (Notes are the exception to E2E: they are plaintext in the
// database. The admin API never exposes them, but a `remove` backup contains
// them and anyone with disk access can read them. See docs/ADMIN_API.md.)
//
//   GET    /api/admin/users          -> {users:[{id,email,displayName,role,
//                                        status,createdAt,storageUsedBytes,
//                                        storageQuotaBytes,fileCount}, ...]}
//   PATCH  /api/admin/users/<id>     {role?, suspended?, storageQuotaBytes?}
//                                     -> {user}
//     - role: "user" | "admin". Refused if it would leave zero admins.
//     - suspended: true blocks login and immediately drops that user's live
//       sessions/API-key auth; false re-enables. Refused if it would suspend
//       the last remaining admin.
//     - storageQuotaBytes: an integer, or null for unlimited.
//
// Account lifecycle (all admin + session only; none can target yourself, and
// none can remove the last admin):
//   POST   /api/admin/users/<id>/remove   -> {removedUserId,tombstoneId,storageRemoved}
//     "Backup + temp remove": snapshots the account (rows as JSON + its
//     still-encrypted blobs) into BACKUP_DIR/<id>_<utc>/, then deletes the live
//     account. Reversible only in the sense that the backup exists on disk —
//     there is no restore endpoint.
//   GET    /api/admin/removed-users       -> {removedUsers:[{id,originalUserId,
//                                            email,displayName,removedAt,removedBy}]}
//   POST   /api/admin/users/<id>/wipe     {confirmEmail}  -> {wiped,storageRemoved}
//     PERMANENT, no backup: deletes a live account and its stored files.
//   POST   /api/admin/removed-users/<id>/wipe  {confirmEmail}  -> {wiped}
//     PERMANENT: deletes a removed account's backup bundle and its tombstone.
// The two wipe routes require confirmEmail to equal the account's email exactly.
void registerAdminRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db,
                         FileStore& store, const std::string& backupRoot);

} // namespace routes
