// Profile pictures, stored as one small file per user under AVATAR_DIR (default data/avatars).
#include "routes/profile.h"
#include "security/request_auth.h"
#include "core/config.h"
#include "utils/logger.h"
#include "routes/events.h"

#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace routes {
namespace {

constexpr size_t kMaxAvatar = 300 * 1024;

std::string avatarDir() { return core::Config::get_instance().get("env", "AVATAR_DIR", "data/avatars"); }
std::string avatarPath(int64_t uid) { return avatarDir() + "/" + std::to_string(uid) + ".img"; }

// Only real images, recognised by their first bytes (the client's Content-Type is not trusted).
std::string sniff(const std::string& b) {
    auto at = [&](size_t i) { return static_cast<unsigned char>(b[i]); };
    if (b.size() > 3 && at(0) == 0xFF && at(1) == 0xD8 && at(2) == 0xFF) return "image/jpeg";
    if (b.size() > 8 && b.compare(0, 8, "\x89PNG\r\n\x1a\n") == 0) return "image/png";
    if (b.size() > 12 && b.compare(0, 4, "RIFF") == 0 && b.compare(8, 4, "WEBP") == 0) return "image/webp";
    return "";
}

} // namespace

int64_t avatarVersion(int64_t uid) {
    // stat() mtime: real Unix seconds (std::filesystem's clock has a different epoch).
    struct stat st{};
    if (::stat(avatarPath(uid).c_str(), &st) != 0) return 0;
    return static_cast<int64_t>(st.st_mtim.tv_sec) * 1000 + st.st_mtim.tv_nsec / 1000000;   // ms: changes on every save
}

void registerProfileRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db) {
    CROW_ROUTE(app, "/api/auth/me/avatar").methods(crow::HTTPMethod::PUT)
    ([&db](const crow::request& req) {
        auto uid = security::authenticateSession(req, db);
        if (!uid) return http::jsonError(401, "unauthorized");
        if (req.body.empty() || req.body.size() > kMaxAvatar) return http::jsonError(413, "picture must be under 300 KB");
        if (sniff(req.body).empty()) return http::jsonError(415, "picture must be a JPEG, PNG or WebP image");
        std::error_code ec;
        fs::create_directories(avatarDir(), ec);
        ::chmod(avatarDir().c_str(), S_IRWXU);
        const std::string tmp = avatarPath(*uid) + ".tmp";
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            if (!f) return http::jsonError(500, "could not save picture");
            f.write(req.body.data(), static_cast<std::streamsize>(req.body.size()));
        }
        ::chmod(tmp.c_str(), S_IRUSR | S_IWUSR);
        fs::rename(tmp, avatarPath(*uid), ec);
        if (ec) return http::jsonError(500, "could not save picture");
        notifyUser(*uid, "me");
        return http::jsonSuccess(json{{"avatarVersion", avatarVersion(*uid)}}.dump());
    });

    CROW_ROUTE(app, "/api/auth/me/avatar").methods(crow::HTTPMethod::GET)
    ([&db](const crow::request& req) {
        auto uid = security::authenticateSession(req, db);
        if (!uid) return http::jsonError(401, "unauthorized");
        std::ifstream f(avatarPath(*uid), std::ios::binary);
        if (!f) return http::jsonError(404, "no picture");
        std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        const std::string type = sniff(data);
        if (type.empty()) return http::jsonError(404, "no picture");
        crow::response r(200);
        r.body = std::move(data);
        r.set_header("Content-Type", type);
        r.set_header("X-Content-Type-Options", "nosniff");
        r.set_header("Cache-Control", "private, max-age=86400");   // the URL carries ?v=<version>
        r.add_header("Content-Security-Policy", "sandbox; default-src 'none'");
        return r;
    });

    CROW_ROUTE(app, "/api/auth/me/avatar").methods(crow::HTTPMethod::DELETE)
    ([&db](const crow::request& req) {
        auto uid = security::authenticateSession(req, db);
        if (!uid) return http::jsonError(401, "unauthorized");
        std::error_code ec;
        fs::remove(avatarPath(*uid), ec);
        notifyUser(*uid, "me");
        return http::jsonSuccess(R"({"ok":true})");
    });
}

} // namespace routes
