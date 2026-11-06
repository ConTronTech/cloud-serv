#include "http/middleware.h"
#include "utils/logger.h"
#include <nlohmann/json.hpp>
#include <sstream>
#include <cctype>

namespace http {

// Static member initialization
security::RateLimiter* SecurityMiddleware::rate_limiter = nullptr;
size_t SecurityMiddleware::max_body_size = 10 * 1024 * 1024; // 10MB default

// CORS allowed origins (must be before before_handle which references it)
static std::vector<std::string> s_cors_origins;

// Extract the "host[:port]" authority from an Origin/Referer URL, lowercased.
// Returns "" if the URL has no scheme://authority (fail closed at the call site).
static std::string authorityOf(const std::string& url) {
    auto p = url.find("://");
    if (p == std::string::npos) return "";
    std::string rest = url.substr(p + 3);
    auto slash = rest.find('/');
    if (slash != std::string::npos) rest = rest.substr(0, slash);
    for (char& c : rest) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return rest; // host[:port]
}

void SecurityMiddleware::before_handle(crow::request& req, crow::response& res, context& ctx) {
    ctx.start_time = std::chrono::steady_clock::now();

    // Handle CORS preflight
    if (req.method == crow::HTTPMethod::OPTIONS) {
        std::string origin = req.get_header_value("Origin");
        bool allowed = false; // no CORS origins configured => deny cross-origin (same-origin never preflights)
        for (const auto& o : s_cors_origins) {
            if (o == origin || o == "*") { allowed = true; break; }
        }
        if (allowed && !origin.empty()) {
            res.add_header("Access-Control-Allow-Origin", origin);
            res.add_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
            res.add_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key");
            res.add_header("Access-Control-Max-Age", "3600");
            res.add_header("Access-Control-Allow-Credentials", "true");
        }
        res.code = 204;
        res.end();
        return;
    }

    // Resolve real client IP
    std::string direct_ip = req.remote_ip_address;
    std::string forwarded = req.get_header_value("X-Forwarded-For");

    if (rate_limiter) {
        ctx.client_ip = rate_limiter->resolveClientIp(direct_ip, forwarded);
    } else {
        ctx.client_ip = direct_ip;
    }

    // Rate limit check
    if (rate_limiter) {
        bool isWrite = (req.method != crow::HTTPMethod::GET &&
                        req.method != crow::HTTPMethod::HEAD &&
                        req.method != crow::HTTPMethod::OPTIONS);

        // Credentials present = throttle, never ban (see RateLimiter::check). Validity is
        // checked by the route as usual; a fake header only buys slowing down instead of a ban.
        const std::string cookie = req.get_header_value("Cookie");
        const bool credentialed = !req.get_header_value("Authorization").empty() ||
                                  !req.get_header_value("X-API-Key").empty() ||
                                  cookie.find("session=") != std::string::npos;
        auto d = rate_limiter->check(ctx.client_ip, isWrite, credentialed);
        if (d != security::RateLimiter::Decision::Allow) {
            res.code = 429;
            res.add_header("Content-Type", "application/json");
            res.add_header("Retry-After", d == security::RateLimiter::Decision::Banned ? "60" : "2");
            res.write("{\"error\":\"too many requests\"}");
            res.end();
            return;
        }
    }

    // CSRF check — state-changing requests from browser must have matching origin
    if (req.method != crow::HTTPMethod::GET &&
        req.method != crow::HTTPMethod::HEAD &&
        req.method != crow::HTTPMethod::OPTIONS) {
        
        std::string origin = req.get_header_value("Origin");
        std::string referer = req.get_header_value("Referer");
        std::string apiKey = req.get_header_value("X-API-Key");
        
        // If request has API key, it's an agent/script — skip CSRF check
        // If no origin AND no referer, it's a direct curl — skip CSRF check
        // If origin/referer present, it's a browser — verify it's from allowed origin
        if (apiKey.empty() && (!origin.empty() || !referer.empty())) {
            bool originOk = false;
            std::string checkUrl = origin.empty() ? referer : origin;
            // Compare the request's origin AUTHORITY (host[:port]) exactly — never a
            // substring — so "victimhost.attacker.com" can't satisfy "victimhost".
            std::string reqAuth = authorityOf(checkUrl);

            if (!reqAuth.empty()) {
                // True same-origin: authority equals our own Host header.
                std::string host = req.get_header_value("Host");
                for (char& c : host) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (!host.empty() && reqAuth == host) originOk = true;

                // Or an explicitly allow-listed CORS origin (exact authority match).
                if (!originOk) {
                    for (const auto& o : s_cors_origins) {
                        if (o == "*" || reqAuth == authorityOf(o)) { originOk = true; break; }
                    }
                }
            }

            if (!originOk) {
                utils::Logger::get_instance().warn("CSRF blocked: origin=" + origin +
                    " referer=" + referer + " from " + ctx.client_ip);
                res.code = 403;
                res.add_header("Content-Type", "application/json");
                res.write("{\"error\":\"cross-origin request blocked\"}");
                res.end();
                return;
            }
        }
    }

    // Body size check
    if (req.body.size() > max_body_size) {
        res.code = 413;
        res.add_header("Content-Type", "application/json");
        res.write("{\"error\":\"payload too large\"}");
        res.end();
        return;
    }
}

void SecurityMiddleware::after_handle(crow::request& req, crow::response& res, context& ctx) {
    // Inject security headers on every response
    addSecurityHeaders(res);

    // CORS origin header on actual requests
    if (!s_cors_origins.empty()) {
        std::string origin = req.get_header_value("Origin");
        for (const auto& o : s_cors_origins) {
            if (o == origin || o == "*") {
                res.add_header("Access-Control-Allow-Origin", origin);
                res.add_header("Access-Control-Allow-Credentials", "true");
                break;
            }
        }
    }

    // Log request
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - ctx.start_time);

    std::ostringstream log;
    log << ctx.client_ip << " "
        << crow::method_name(req.method) << " "
        << req.url << " "
        << res.code << " "
        << res.body.size() << "b "
        << duration.count() << "ms";

    if (res.code >= 400) {
        utils::Logger::get_instance().warn("[REQUEST] " + log.str());
    } else {
        utils::Logger::get_instance().info("[REQUEST] " + log.str());
    }
}

void setCorsOrigins(const std::vector<std::string>& origins) {
    s_cors_origins = origins;
}

void addSecurityHeaders(crow::response& res) {
    res.add_header("X-Content-Type-Options", "nosniff");
    res.add_header("X-Frame-Options", "DENY");
    res.add_header("X-XSS-Protection", "1; mode=block");
    // TLS is in-daemon; browsers ignore HSTS on plain HTTP, so it's safe to always send.
    // No includeSubDomains: the box is reached by IP / tailnet name.
    res.add_header("Strict-Transport-Security", "max-age=31536000");
    res.add_header("Referrer-Policy", "strict-origin-when-cross-origin");
    // blob: is needed for client-side decrypted media (preview <video>/<audio>/<img>
    // and the PDF <iframe>); data: for canvas-generated E2E thumbnails.
    res.add_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; media-src 'self' blob:; frame-src blob:; connect-src 'self'");
}

crow::response jsonError(int code, const std::string& message) {
    crow::response res(code);
    res.add_header("Content-Type", "application/json");
    // Use nlohmann::json to properly escape special characters in message
    // Prevents broken JSON from quotes, backslashes, or control chars in error text
    nlohmann::json j = {{"error", message}};
    res.write(j.dump());
    return res;
}

crow::response jsonSuccess(const std::string& jsonBody) {
    crow::response res(200);
    res.add_header("Content-Type", "application/json");
    res.write(jsonBody);
    return res;
}

} // namespace http
