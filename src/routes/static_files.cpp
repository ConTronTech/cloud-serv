#include "routes/static_files.h"
#include <fstream>
#include <sstream>

namespace routes {

namespace {
// True if `name` is safe to join onto webDir. Crow's own routing already
// guarantees a <string> capture never contains '/', so this only needs to
// reject the remaining traversal/oddity cases: a literal ".." segment, a
// backslash, control characters, and empty.
bool safeStaticName(const std::string& name) {
    if (name.empty() || name == "..") return false;
    for (unsigned char c : name) {
        if (c < 0x20 || c == '\\') return false;
    }
    return true;
}
} // namespace

void registerStaticRoutes(crow::App<http::SecurityMiddleware>& app,
                          const std::string& webDir) {

    // Root -> index.html. webDir is operator config, not user input, so it
    // needs no sanitization here — and calling set_static_file_info() would
    // be actively wrong: Crow's sanitizer (utility::sanitize_filename)
    // mangles ANY leading '/' to '_' to block an absolute-path traversal
    // vector, which breaks a legitimate absolute WEB_DIR (e.g. a Docker or
    // systemd deployment that isn't run from the repo root). Use the
    // *_unsafe variant, which skips that sanitizer — "unsafe" only for
    // attacker-controlled input, which webDir is not.
    CROW_ROUTE(app, "/")
    ([webDir]() {
        crow::response res;
        res.set_static_file_info_unsafe(webDir + "/index.html");
        return res;
    });

    // Single-segment static assets (app.js, style.css, manifest.webmanifest,
    // sw.js, favicon.svg, ...). Multi-segment /api/... routes are unaffected.
    CROW_ROUTE(app, "/<string>")
    ([webDir](const crow::request&, crow::response& res, std::string name) {
        if (!safeStaticName(name)) { res.code = 404; res.end(); return; }
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
        // *_unsafe to sidestep the same absolute-webDir mangling as above —
        // safeStaticName() already rejected '..'/backslash/control chars, and
        // Crow's routing guarantees no '/' can reach `name`.
        res.set_static_file_info_unsafe(webDir + "/" + name);
        res.end();
    });
}

} // namespace routes
