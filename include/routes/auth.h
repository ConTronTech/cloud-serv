#pragma once

#include <crow.h>
#include "http/middleware.h"
#include "db/database.h"

namespace routes {

// Registers account + session + API-key endpoints:
//   POST   /api/auth/register       {email,password,displayName?} -> {token,user}
//   POST   /api/auth/login          {email,password}              -> {token,user}
//   GET    /api/auth/me                                           -> {user}
//   POST   /api/auth/logout                                       -> {ok}
//   POST   /api/auth/api-keys       {name?}          -> {key, info}   (key shown once)  (session auth only; API keys rejected)
//   GET    /api/auth/api-keys                        -> {keys:[...]}
//   DELETE /api/auth/api-keys/<id>                   -> {ok}
//
// sessionSeconds controls how long a login token stays valid.
void registerAuthRoutes(crow::App<http::SecurityMiddleware>& app,
                        CloudDB& db, int sessionSeconds);

} // namespace routes
