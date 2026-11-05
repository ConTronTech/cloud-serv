#pragma once
// Live change notifications over one WebSocket per signed-in tab: GET /api/events (upgrade).
// Messages are tiny JSON hints ({"type":"requests"} ...); the client then refetches what it
// shows. No data travels over the socket, so it never needs its own access checks per item.
#include <crow.h>
#include <cstdint>
#include <string>
#include "http/middleware.h"
#include "db/database.h"

namespace routes {

void registerEventRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db);
void notifyAdmins(const std::string& type);                 // requests | invites | users
void notifyUser(int64_t userId, const std::string& type);   // devices | ...

} // namespace routes
