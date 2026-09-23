#pragma once

#include <string>

namespace security {
namespace tls {

// Ensures a usable self-signed server certificate exists at cert_path/key_path.
// Generates a fresh EC P-256 cert (10y) when the files are missing/unreadable,
// or when the existing cert's SAN does not cover the box's Tailscale IP.
// SAN: 127.0.0.1, localhost, every local IPv4 interface, plus the Tailscale IP.
// Key is chmod 0600, its parent directory 0700. Throws std::runtime_error on failure.
// Returns true if a new cert was generated.
bool ensure_server_cert(const std::string& cert_path, const std::string& key_path);

// Tailscale IPv4 of this box ("tailscale ip -4", falling back to an interface
// in 100.64.0.0/10). Empty string if none detected.
std::string detect_tailscale_ip();

} // namespace tls
} // namespace security
