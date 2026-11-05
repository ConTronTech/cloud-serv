#pragma once

#include <crow.h>
#include "http/middleware.h"
#include "db/database.h"

namespace routes {

// Trusted devices: each browser holds its own key pair (private half never leaves it);
// the server only stores the DEK sealed to each approved device's public key.
// All endpoints need a browser session (API keys are refused).
//   GET    /api/devices                     -> {devices:[...]}
//   POST   /api/devices        {name, publicKey, wrappedDek?}  -> {device}   (no wrappedDek = pending)
//   GET    /api/devices/<id>/key            -> {status, wrappedDek}
//   POST   /api/devices/<id>/approve        {wrappedDek} -> {ok}
//   DELETE /api/devices/<id>                -> {ok}
//   POST   /api/keys/init   {wrappedDekRecovery}  -> {ok}   (first-time encryption setup, keyless accounts only)
void registerDeviceRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db);

} // namespace routes
