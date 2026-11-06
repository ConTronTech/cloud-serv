#pragma once
#include <crow.h>
#include "http/middleware.h"
#include "db/database.h"
#include "storage/tree_store.h"

namespace routes {
// GET /api/trash, POST /api/trash/restore, DELETE /api/trash/item?id=, DELETE /api/trash
void registerTrashRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db, TreeStore& tree);
}
