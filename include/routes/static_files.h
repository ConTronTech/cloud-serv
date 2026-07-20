#pragma once

#include <crow.h>
#include <string>
#include "http/middleware.h"

namespace routes {

// Serves the PWA from webDir at the site root, same-origin with the API:
//   GET /            -> <webDir>/index.html
//   GET /<file>      -> <webDir>/<file>   (single path segment; never /api/...)
// Path is sanitized by Crow's set_static_file_info (no traversal).
void registerStaticRoutes(crow::App<http::SecurityMiddleware>& app,
                          const std::string& webDir);

} // namespace routes
