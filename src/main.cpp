#include <crow.h>
#include <sys/stat.h>
#include "core/config.h"
#include "db/database.h"
#include "storage/file_store.h"
#include "http/middleware.h"
#include "cli/admin_cli.h"
#include "routes/admin.h"
#include "routes/auth.h"
#include "routes/oidc.h"
#include "routes/devices.h"
#include "routes/profile.h"
#include "routes/files.h"
#include "routes/fs.h"
#include "routes/notes.h"
#include "routes/uploads.h"
#include "routes/static_files.h"
#include "security/rate_limiter.h"
#include "security/sanitizer.h"
#include "security/tls.h"
#include "utils/logger.h"
#include "utils/string_utils.h"

#include <nlohmann/json.hpp>
#include <filesystem>
#include <iostream>
#include <atomic>
#include <thread>
#include <chrono>
#include <mutex>
#include <condition_variable>

// Routes Crow's own internal log messages through our logger, and drops the
// benign EPIPE line ("Writing stopped premature") that fires whenever a client
// disconnects before we finish writing a response — common with browsers and
// not actionable, so it shouldn't spam the log at ERROR.
class CrowLogRouter : public crow::ILogHandler {
public:
    void log(const std::string& message, crow::LogLevel level) override {
        if (message.find("Writing stopped premature") != std::string::npos ||
            message.find("buffer write error") != std::string::npos) {
            return;
        }
        auto& log = utils::Logger::get_instance();
        switch (level) {
            case crow::LogLevel::Debug:    log.debug(message); break;
            case crow::LogLevel::Info:     log.info(message); break;
            case crow::LogLevel::Warning:  log.warn(message); break;
            case crow::LogLevel::Error:
            case crow::LogLevel::Critical: log.error(message); break;
        }
    }
};
static CrowLogRouter crow_log_router;

int main(int argc, char* argv[]) {
    // `cloud_serv admin ...`: local administration straight on the database.
    if (argc > 1 && std::string(argv[1]) == "admin") return cli::runAdminCli(argc - 1, argv + 1);

    std::string config_file = "config.env";
    if (argc > 1) config_file = argv[1];

    try {
        // 1. Config
        core::Config& config = core::Config::get_instance();
        config.load(config_file);

        // 2. Logger
        std::string log_level_str = config.get("env", "LOG_LEVEL", "INFO");
        utils::LogLevel log_level = utils::LogLevel::INFO;
        if (log_level_str == "DEBUG") log_level = utils::LogLevel::DEBUG;
        else if (log_level_str == "WARN") log_level = utils::LogLevel::WARN;
        else if (log_level_str == "ERROR") log_level = utils::LogLevel::ERROR;
        utils::Logger::get_instance().init(log_level);
        crow::logger::setHandler(&crow_log_router); // route + de-noise Crow's own logs
        utils::Logger::get_instance().info("===========================================");
        utils::Logger::get_instance().info("cloud-serv starting...");
        utils::Logger::get_instance().info("===========================================");

        // 3. Rate limiter
        security::RateLimiter rateLimiter;
        rateLimiter.init(
            config.get_bool("env", "RATE_LIMIT_ENABLED", true),
            config.get_int("env", "READ_RPM", 1200),
            config.get_int("env", "WRITE_RPM", 600),
            config.get_int("env", "BURST_SIZE", 200),
            config.get_int("env", "BAN_THRESHOLD", 100),
            config.get_int("env", "BAN_DURATION", 300)
        );
        std::string proxyStr = config.get("env", "TRUSTED_PROXIES", "");
        if (!proxyStr.empty()) {
            auto proxies = utils::StringUtils::split(proxyStr, ',');
            for (auto& p : proxies) p = utils::StringUtils::trim(p);
            rateLimiter.setTrustedProxies(proxies);
        }

        // 4. Crow app + middleware
        //    Crow installs its own SIGINT/SIGTERM handlers (signals_ defaults to
        //    {SIGINT, SIGTERM}); app.run() returns cleanly when Ctrl+C is pressed.
        crow::App<http::SecurityMiddleware> app;
        http::SecurityMiddleware::rate_limiter = &rateLimiter;
        // Cloud stores media, so allow large bodies by default (256 MB).
        http::SecurityMiddleware::max_body_size =
            static_cast<size_t>(config.get_int("env", "MAX_BODY_SIZE", 268435456));

        // 6. CORS
        std::string corsStr = config.get("env", "CORS_ORIGINS", "");
        if (!corsStr.empty()) {
            auto origins = utils::StringUtils::split(corsStr, ',');
            for (auto& o : origins) o = utils::StringUtils::trim(o);
            http::setCorsOrigins(origins);
            utils::Logger::get_instance().info("CORS: " + std::to_string(origins.size()) + " origins allowed");
        } else {
            utils::Logger::get_instance().info("CORS: no origins configured (same-origin only)");
        }

        // 7. Data layer
        std::string db_path = config.get("env", "DB_PATH", "data/cloud.db");
        std::string storage_dir = config.get("env", "STORAGE_DIR", "data/storage");
        // Make sure the DB's parent directory exists before SQLite opens the file.
        {
            std::error_code ec;
            std::filesystem::path p(db_path);
            if (p.has_parent_path()) {
                std::filesystem::create_directories(p.parent_path(), ec);
                ::chmod(p.parent_path().c_str(), S_IRWXU);  // owner-only DB directory
            }
        }
        CloudDB db(db_path);
        FileStore store(storage_dir);

        int sessionSeconds = config.get_int("env", "SESSION_SECONDS", 30 * 24 * 60 * 60);

        // 8. Routes
        CROW_ROUTE(app, "/api/health")
        ([]() {
            nlohmann::json j = {{"status", "ok"}, {"service", "cloud-serv"}};
            return http::jsonSuccess(j.dump());
        });
        // Max size of a single assembled file (chunked uploads can exceed the
        // per-request body limit; this caps the total). In MB to stay within int.
        int64_t maxFileMb = config.get_int("env", "MAX_FILE_MB", 5120); // 5 GB
        int64_t maxFileBytes = maxFileMb * 1024 * 1024;

        routes::registerAuthRoutes(app, db, sessionSeconds);
        routes::registerOidcRoutes(app, db, sessionSeconds);
        routes::registerDeviceRoutes(app, db);
        routes::registerProfileRoutes(app, db);
        routes::registerFileRoutes(app, db, store);
        routes::registerFsRoutes(app, db, store);
        routes::registerNoteRoutes(app, db);
        routes::registerUploadRoutes(app, db, store, maxFileBytes);
        std::string backupDir = config.get("env", "BACKUP_DIR", "data/backups");
        routes::registerAdminRoutes(app, db, store, backupDir);
        routes::registerSignupAdminRoutes(app, db);

        // Serve the PWA (same-origin with the API).
        std::string web_dir = config.get("env", "WEB_DIR", "web");
        routes::registerStaticRoutes(app, web_dir);

        // 8b. TLS (self-signed, in-daemon). Regenerates the cert if it doesn't
        //     cover the box's current Tailscale IP. TLS_ENABLED=false = plain HTTP (dev).
        bool tlsEnabled = config.get_bool("env", "TLS_ENABLED", true);
        if (tlsEnabled) {
            std::string certPath = config.get("env", "TLS_CERT_PATH", "data/tls/server.crt");
            std::string keyPath = config.get("env", "TLS_KEY_PATH", "data/tls/server.key");
            security::tls::ensure_server_cert(certPath, keyPath,
                config.get_bool("env", "TLS_PREFER_TAILSCALE_CERT", true));
            app.ssl_file(certPath, keyPath);
        } else {
            utils::Logger::get_instance().warn("TLS disabled (TLS_ENABLED=false) — serving plain HTTP");
        }

        // 9. Startup banner
        int port = config.get_int("env", "PORT", 8080);
        utils::Logger::get_instance().info(std::string("API @ ") + (tlsEnabled ? "https" : "http") +
                                           "://0.0.0.0:" + std::to_string(port));
        utils::Logger::get_instance().info("  POST   /api/auth/register");
        utils::Logger::get_instance().info("  POST   /api/auth/login");
        utils::Logger::get_instance().info("  GET    /api/auth/me");
        utils::Logger::get_instance().info("  POST   /api/auth/logout");
        utils::Logger::get_instance().info("  POST   /api/auth/api-keys      (create, shown once)");
        utils::Logger::get_instance().info("  GET    /api/auth/api-keys");
        utils::Logger::get_instance().info("  DELETE /api/auth/api-keys/<id>");
        utils::Logger::get_instance().info("  POST   /api/files              (X-Filename + raw body)");
        utils::Logger::get_instance().info("  GET    /api/files");
        utils::Logger::get_instance().info("  GET    /api/files/<id>         (download)");
        utils::Logger::get_instance().info("  GET    /api/files/<id>/content (inline, Range/playback)");
        utils::Logger::get_instance().info("  DELETE /api/files/<id>");
        utils::Logger::get_instance().info("  POST   /api/uploads/init      (chunked upload)");
        utils::Logger::get_instance().info("  PUT    /api/uploads/<id>      (chunk, X-Offset)");
        utils::Logger::get_instance().info("  POST   /api/uploads/<id>/complete");
        utils::Logger::get_instance().info("  GET    /api/notes");
        utils::Logger::get_instance().info("  POST   /api/notes");
        utils::Logger::get_instance().info("  GET    /api/notes/<id>");
        utils::Logger::get_instance().info("  PUT    /api/notes/<id>");
        utils::Logger::get_instance().info("  DELETE /api/notes/<id>");
        utils::Logger::get_instance().info("  GET    /api/admin/users        (admin only)");
        utils::Logger::get_instance().info("  PATCH  /api/admin/users/<id>   (admin only: role/suspend/quota)");
        utils::Logger::get_instance().info("  POST   /api/admin/users/<id>/remove   (admin only: backup + remove data)");
        utils::Logger::get_instance().info("  POST   /api/admin/users/<id>/wipe     (admin only: permanent)");
        utils::Logger::get_instance().info("  GET    /api/admin/removed-users       (admin only)");
        utils::Logger::get_instance().info("  POST   /api/admin/users/<id>/restore  (admin only: restore a removed account's data)");
        utils::Logger::get_instance().info("Press Ctrl+C to stop");

        // 10. Periodic maintenance (purge expired sessions + idle rate buckets)
        //     runs in the background on an interruptible 1s tick, so shutdown is
        //     immediate rather than waiting out a sleep.
        std::atomic<bool> running{true};
        std::mutex mtx;
        std::condition_variable cv;
        std::thread maintenance([&]() {
            int counter = 0;
            while (running.load()) {
                {
                    std::unique_lock<std::mutex> lk(mtx);
                    cv.wait_for(lk, std::chrono::seconds(1), [&] { return !running.load(); });
                }
                if (!running.load()) break;
                if (++counter >= 300) {
                    counter = 0;
                    rateLimiter.cleanupOldClients();
                    int purged = db.purgeExpiredSessions();
                    if (purged > 0)
                        utils::Logger::get_instance().info("Purged " + std::to_string(purged) + " expired sessions");
                }
            }
        });

        // 11. Run the server. Blocks here until SIGINT/SIGTERM (Crow's own signal
        //     handling stops the io_context and run() returns) — that's the clean
        //     Ctrl+C path.
        app.loglevel(crow::LogLevel::Warning);
        try {
            app.port(static_cast<uint16_t>(port)).multithreaded().run();
        } catch (const std::exception& e) {
            utils::Logger::get_instance().error("Server error: " + std::string(e.what()));
        }

        // 12. Graceful shutdown — always stop + join the maintenance thread,
        //     even if run() threw (otherwise ~thread would std::terminate).
        utils::Logger::get_instance().info("Shutting down...");
        {
            std::lock_guard<std::mutex> lk(mtx);
            running.store(false);
        }
        cv.notify_all();
        if (maintenance.joinable()) maintenance.join();
        utils::Logger::get_instance().info("Server stopped");

    } catch (const std::exception& e) {
        std::cerr << "Fatal: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
