#pragma once

#include <crow.h>
#include "http/middleware.h"
#include "db/database.h"
#include "storage/file_store.h"

namespace routes {

// Filesystem/tree endpoints (all require auth):
//   GET    /api/fs?folder=<id>   -> {folder, breadcrumbs, folders, files}
//   POST   /api/folders          {parentId?, name}       -> {folder}
//   PATCH  /api/folders/<id>     {name?, parentId?}       -> {folder}   (rename/move)
//   DELETE /api/folders/<id>     -> {ok}   (recursive; frees blobs)
//   PATCH  /api/files/<id>       {name?, folderId?}       -> {file}     (rename/move)
void registerFsRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db, FileStore& store);

} // namespace routes
