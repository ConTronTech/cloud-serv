#pragma once

#include <crow.h>
#include "http/middleware.h"
#include "db/database.h"

namespace routes {

// "Sign in with authentik" (OIDC) + linked identities:
//   GET    /api/auth/oidc/config                 -> {enabled, label}
//   GET    /api/auth/oidc/start?mode=login|link  -> 302 to the identity provider
//   GET    /api/auth/oidc/callback               -> 302 back to the app (session cookie set)
//   GET    /api/auth/identities                  -> {identities:[...], localLogin}
//   DELETE /api/auth/identities/<id>             -> {ok}   (refused if it is the last way in)
void registerOidcRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db, int sessionSeconds);

} // namespace routes
