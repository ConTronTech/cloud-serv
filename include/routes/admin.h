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
// route to build. Notes are end-to-end encrypted as well; only a legacy note not
// yet upgraded by its owner is still plaintext on disk (see docs/ADMIN_API.md).
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
// Account lifecycle (admin + session only; none can target yourself or the last
// active admin):
//   POST   /api/admin/users/<id>/remove   {reason?} -> {removedUserId,status,storageRemoved}
//     "Backup + temp remove": snapshots the account's data (rows as JSON + its
//     still-encrypted blobs) into BACKUP_DIR/<id>_<utc>/, then deletes that data.
//     THE ACCOUNT STAYS (status "removed", credentials + E2E key material kept), so
//     its owner can sign in, see a notice, and later get everything back.
//   POST   /api/admin/users/<id>/restore  -> {restoredUserId,status,folders,files,notes}
//     Puts a removed account's data back exactly as it was (same ids).
//   GET    /api/admin/removed-users       -> {removedUsers:[{id,originalUserId,email,
//                                            displayName,removedAt,removedBy,reason,backupBytes}]}
//   POST   /api/admin/users/<id>/wipe     {confirmEmail}  -> {wiped,storageRemoved,backupRemoved}
//     PERMANENT: deletes the account, its data and (if removed) its backup.
// wipe requires confirmEmail to equal the account's email exactly.
// Sign-up approval queue + one-time invite codes (admin + session only):
//   GET    /api/admin/requests                 -> {requests:[{id,email,displayName,createdAt,ip,note}]}
//   POST   /api/admin/requests/<id>/approve    -> {ok}
//   POST   /api/admin/requests/<id>/deny       -> {ok}     (deletes the pending account)
//   GET    /api/admin/invites                  -> {invites:[...]}   (codes are never shown again)
//   POST   /api/admin/invites  {label?, expiresDays?}  -> {code, invite}   (code shown ONCE)
//   DELETE /api/admin/invites/<id>             -> {ok}     (only while unused)
void registerSignupAdminRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db);

void registerAdminRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db,
                         FileStore& store, const std::string& backupRoot);

} // namespace routes
