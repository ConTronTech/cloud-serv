#pragma once

#include <crow.h>
#include "http/middleware.h"
#include "db/database.h"

namespace routes {

// Registers admin-only account-management endpoints. Every route requires a
// login session (never an API key — same rule as /api/auth/api-keys) AND the
// caller's role to be "admin".
//
// These endpoints manage ACCOUNTS ONLY — who can log in, their role, and how
// much storage they're allowed. None of them can read, list, or restore a
// user's files, folders, or notes: that data is end-to-end encrypted and the
// server never has a way to present it even to an admin. This is an
// architectural boundary, not a policy choice enforced by omission in the UI.
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
void registerAdminRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db);

} // namespace routes
