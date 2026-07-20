#include <crow.h>
#include "core/config.h"
#include "db/database.h"
#include "storage/file_store.h"
#include "http/middleware.h"
#include "routes/auth.h"
#include "routes/files.h"
#include "security/rate_limiter.h"
#include "security/sanitizer.h"
#include "utils/logger.h"
#include "utils/string_utils.h"

#include <nlohmann/json.hpp>
#include <filesystem>
#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>

static std::atomic<bool> shutdown_requested{false};

static void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        shutdown_requested.store(true);
    }
}

int main(int argc, char* argv[]) {
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
        utils::Logger::get_instance().info("===========================================");
        utils::Logger::get_instance().info("cloud-serv starting...");
        utils::Logger::get_instance().info("===========================================");

        // 3. Rate limiter
        security::RateLimiter rateLimiter;
        rateLimiter.init(
            config.get_bool("env", "RATE_LIMIT_ENABLED", true),
            config.get_int("env", "READ_RPM", 240),
            config.get_int("env", "WRITE_RPM", 60),
            config.get_int("env", "BURST_SIZE", 30),
            config.get_int("env", "BAN_THRESHOLD", 10),
            config.get_int("env", "BAN_DURATION", 600)
        );
        std::string proxyStr = config.get("env", "TRUSTED_PROXIES", "");
        if (!proxyStr.empty()) {
            auto proxies = utils::StringUtils::split(proxyStr, ',');
            for (auto& p : proxies) p = utils::StringUtils::trim(p);
            rateLimiter.setTrustedProxies(proxies);
        }

        // 4. Signal handlers
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        // 5. Crow app + middleware
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
            if (p.has_parent_path()) std::filesystem::create_directories(p.parent_path(), ec);
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
        routes::registerAuthRoutes(app, db, sessionSeconds);
        routes::registerFileRoutes(app, db, store);

        // 9. Startup banner
        int port = config.get_int("env", "PORT", 8080);
        utils::Logger::get_instance().info("API @ http://0.0.0.0:" + std::to_string(port));
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
        utils::Logger::get_instance().info("  DELETE /api/files/<id>");
        utils::Logger::get_instance().info("Press Ctrl+C to stop");

        // 10. Run server on its own thread
        std::thread server_thread([&]() {
            try {
                app.loglevel(crow::LogLevel::Warning);
                app.port(static_cast<uint16_t>(port)).multithreaded().run();
            } catch (const std::exception& e) {
                utils::Logger::get_instance().error("Server error: " + std::string(e.what()));
            }
        });

        // 11. Periodic maintenance: purge expired sessions + idle rate buckets.
        int cleanup_counter = 0;
        while (!shutdown_requested.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            if (++cleanup_counter >= 300) {
                cleanup_counter = 0;
                rateLimiter.cleanupOldClients();
                int purged = db.purgeExpiredSessions();
                if (purged > 0)
                    utils::Logger::get_instance().info("Purged " + std::to_string(purged) + " expired sessions");
            }
        }

        // 12. Graceful shutdown
        utils::Logger::get_instance().info("Shutting down...");
        app.stop();
        if (server_thread.joinable()) server_thread.join();
        utils::Logger::get_instance().info("Server stopped");

    } catch (const std::exception& e) {
        std::cerr << "Fatal: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
