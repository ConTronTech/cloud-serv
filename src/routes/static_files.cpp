#include "routes/static_files.h"

namespace routes {

void registerStaticRoutes(crow::App<http::SecurityMiddleware>& app,
                          const std::string& webDir) {

    // Root -> index.html
    CROW_ROUTE(app, "/")
    ([webDir]() {
        crow::response res;
        res.set_static_file_info(webDir + "/index.html");
        return res;
    });

    // Single-segment static assets (app.js, style.css, manifest.webmanifest,
    // sw.js, favicon.ico, ...). Multi-segment /api/... routes are unaffected.
    CROW_ROUTE(app, "/<string>")
    ([webDir](const crow::request&, crow::response& res, std::string name) {
        // set_static_file_info sanitizes the path (blocks traversal / device names).
        res.set_static_file_info(webDir + "/" + name);
        res.end();
    });
}

} // namespace routes
