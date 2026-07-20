#pragma once

#include <crow.h>
#include "http/middleware.h"
#include "db/database.h"

namespace routes {

// Registers per-user notes endpoints (all require auth):
//   GET    /api/notes          -> {notes:[{id,title,createdAt,updatedAt}, ...]}
//   POST   /api/notes          {title?,body?}      -> {note}
//   GET    /api/notes/<id>     -> {note}   (full, with body)
//   PUT    /api/notes/<id>     {title?,body?}      -> {note}
//   DELETE /api/notes/<id>     -> {ok}
void registerNoteRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db);

} // namespace routes
