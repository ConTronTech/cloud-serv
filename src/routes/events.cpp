#include "routes/events.h"
#include "security/request_auth.h"
#include "utils/logger.h"

#include <mutex>
#include <unordered_map>

namespace routes {
namespace {

struct Who { int64_t userId = 0; bool admin = false; };
std::mutex mx;
std::unordered_map<crow::websocket::connection*, Who> conns;
constexpr size_t kMaxConns = 200;
constexpr size_t kMaxPerUser = 10;

// Close and error can both fire for one socket; the null check makes the second a no-op.
void forget(crow::websocket::connection& c) {
    std::lock_guard<std::mutex> lk(mx);
    conns.erase(&c);
    delete static_cast<Who*>(c.userdata());
    c.userdata(nullptr);
}

void sendTo(bool adminsOnly, int64_t userId, const std::string& type) {
    const std::string msg = "{\"type\":\"" + type + "\"}";
    std::lock_guard<std::mutex> lk(mx);
    for (auto& [c, w] : conns)
        if ((adminsOnly && w.admin) || (!adminsOnly && w.userId == userId)) c->send_text(msg);
}

} // namespace

void notifyAdmins(const std::string& type) { sendTo(true, 0, type); }
void notifyUser(int64_t userId, const std::string& type) { sendTo(false, userId, type); }
void notifyAll(const std::string& type) {
    const std::string msg = "{\"type\":\"" + type + "\"}";
    std::lock_guard<std::mutex> lk(mx);
    for (auto& [c, w] : conns) c->send_text(msg);
}

void registerEventRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db) {
    CROW_WEBSOCKET_ROUTE(app, "/api/events")
        // Same rules as the API: a browser session (cookie), never an API key; and only
        // same-origin pages (a foreign site can't open it with the user's cookie).
        .onaccept([&db](const crow::request& req, void** ud) {
            const std::string origin = req.get_header_value("Origin"), host = req.get_header_value("Host");
            if (!origin.empty() && origin != "https://" + host && origin != "http://" + host) return false;
            auto uid = security::authenticateSession(req, db);
            if (!uid) return false;
            auto u = db.findUserById(*uid);
            if (!u || u->status != "active") return false;
            {
                std::lock_guard<std::mutex> lk(mx);
                if (conns.size() >= kMaxConns) return false;
                size_t mine = 0;   // one account can't take every slot
                for (auto& [c, w] : conns) if (w.userId == *uid) ++mine;
                if (mine >= kMaxPerUser) return false;
            }
            *ud = new Who{*uid, u->role == "admin"};
            return true;
        })
        .onopen([](crow::websocket::connection& c) {
            auto* w = static_cast<Who*>(c.userdata());
            std::lock_guard<std::mutex> lk(mx);
            if (w) conns[&c] = *w;
        })
        .onmessage([](crow::websocket::connection&, const std::string&, bool) { /* server -> client only */ })
        .onclose([](crow::websocket::connection& c, const std::string&, uint16_t) { forget(c); })
        .onerror([](crow::websocket::connection& c, const std::string&) { forget(c); });
}

} // namespace routes
