#pragma once

#include <crow.h>
#include "security/rate_limiter.h"
#include <string>
#include <chrono>

namespace http {

// Crow middleware — runs on every request
struct SecurityMiddleware {
    struct context {
        std::string client_ip;
        std::chrono::steady_clock::time_point start_time;
    };

    // Shared state (set before app.run())
    static security::RateLimiter* rate_limiter;
    static size_t max_body_size;

    void before_handle(crow::request& req, crow::response& res, context& ctx);
    void after_handle(crow::request& req, crow::response& res, context& ctx);
};

// Set allowed CORS origins
void setCorsOrigins(const std::vector<std::string>& origins);

// Helper to add security headers to a response
void addSecurityHeaders(crow::response& res);

// Helper to create JSON error response
crow::response jsonError(int code, const std::string& message);

// Helper to create JSON success response
crow::response jsonSuccess(const std::string& jsonBody);

} // namespace http
