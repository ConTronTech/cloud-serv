#include "routes/static_files.h"
#include <fstream>
#include <sstream>

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
    // sw.js, favicon.svg, ...). Multi-segment /api/... routes are unaffected.
    CROW_ROUTE(app, "/<string>")
    ([webDir](const crow::request&, crow::response& res, std::string name) {
        auto endsWith = [&](const std::string& suf) {
            return name.size() >= suf.size() &&
                   name.compare(name.size() - suf.size(), suf.size(), suf) == 0;
        };
        // Crow's mime table doesn't know .webmanifest and logs a warning on every
        // request. Serve it directly with the correct type. (name is a single
        // path segment, so no traversal.)
        if (endsWith(".webmanifest")) {
            std::ifstream f(webDir + "/" + name, std::ios::binary);
            if (!f) { res.code = 404; res.end(); return; }
            std::stringstream ss; ss << f.rdbuf();
            res.code = 200;
            res.body = ss.str();
            res.set_header("Content-Type", "application/manifest+json");
            res.end();
            return;
        }
        // set_static_file_info sanitizes the path (blocks traversal / device names).
        res.set_static_file_info(webDir + "/" + name);
        res.end();
    });
}

} // namespace routes
