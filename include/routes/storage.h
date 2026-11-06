#pragma once

#include <crow.h>
#include "http/middleware.h"
#include "db/database.h"

namespace routes {

// Asking for more storage (session only):
//   POST /api/storage-requests        {uploadBytes, message?}  -> {request}   (size of the upload that didn't fit; the server
//                                      asks for usage + upload, rounded up to 100 MB; replaces a pending one)
//   GET  /api/storage-requests/mine   -> {request|null}
// Admins (session + admin role):
//   GET  /api/admin/storage-requests  -> {requests:[{id,email,displayName,usedBytes,quotaBytes,requestedBytes,message,createdAt}]}
//   POST /api/admin/storage-requests/<id>/approve  {grantBytes?}  -> {ok, quotaBytes}   (default: what was asked)
//   POST /api/admin/storage-requests/<id>/deny     -> {ok}
void registerStorageRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db);

} // namespace routes
