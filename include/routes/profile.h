#pragma once

#include <crow.h>
#include <cstdint>
#include <string>
#include "http/middleware.h"
#include "db/database.h"

namespace routes {

// Profile picture (not end-to-end encrypted: it's shown in the app's own UI only).
//   PUT    /api/auth/me/avatar   body: JPEG/PNG/WebP bytes, <= 300 KB  -> {avatarVersion}
//   GET    /api/auth/me/avatar   -> the image (session cookie auth, so <img> can load it)
//   DELETE /api/auth/me/avatar   -> {ok}
void registerProfileRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db);

// 0 if the user has no picture; otherwise a version number for cache-busting.
int64_t avatarVersion(int64_t userId);

} // namespace routes
