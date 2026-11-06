#pragma once

#include <crow.h>
#include "http/middleware.h"
#include "db/database.h"
#include "storage/file_store.h"
#include "storage/tree_store.h"

namespace routes {

// Registers per-user file endpoints (all require auth):
//   POST   /api/files          raw body; X-Filename + Content-Type headers -> {file}
//   GET    /api/files                                                      -> {files:[...]}
//   GET    /api/files/<id>     streams the blob (Content-Disposition: attachment)
//   DELETE /api/files/<id>                                                 -> {ok}
void registerFileRoutes(crow::App<http::SecurityMiddleware>& app,
                        CloudDB& db, FileStore& store, TreeStore& tree);

} // namespace routes
