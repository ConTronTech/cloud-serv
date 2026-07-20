#pragma once

#include <crow.h>
#include <cstdint>
#include "http/middleware.h"
#include "db/database.h"
#include "storage/file_store.h"

namespace routes {

// Chunked / resumable upload endpoints (all require auth):
//   POST   /api/uploads/init            {name, mime?, size?} -> {uploadId, received}
//   GET    /api/uploads/<id>            -> {received, size, name}   (resume/status)
//   PUT    /api/uploads/<id>            raw chunk body + X-Offset header -> {received}
//   POST   /api/uploads/<id>/complete   -> {file}
//   DELETE /api/uploads/<id>            -> {ok}   (abort)
//
// maxFileBytes caps the total size of a single assembled file.
void registerUploadRoutes(crow::App<http::SecurityMiddleware>& app,
                          CloudDB& db, FileStore& store, int64_t maxFileBytes);

} // namespace routes
