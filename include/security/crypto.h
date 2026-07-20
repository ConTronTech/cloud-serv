#pragma once

#include <string>

namespace security {

// Small crypto helper for the multi-user layer. Backed by OpenSSL (libssl/libcrypto).
// Reuses the /dev/urandom token idea from Auth, adds password hashing + SHA-256
// so API keys and session tokens are only ever stored as hashes.
class Crypto {
public:
    // Cryptographically-random lowercase hex string of `nbytes` random bytes.
    static std::string randomHex(size_t nbytes = 32);

    // SHA-256 of input, lowercase hex. Used to hash API keys / session tokens
    // before they touch the database.
    static std::string sha256Hex(const std::string& input);

    // Hash a password for storage. Format: "pbkdf2$<iters>$<saltHex>$<hashHex>".
    static std::string hashPassword(const std::string& password);

    // Verify a password against a stored "pbkdf2$..." string, constant-time.
    static bool verifyPassword(const std::string& password, const std::string& stored);

    // Constant-time string comparison (avoids leaking match length via timing).
    static bool constantTimeEquals(const std::string& a, const std::string& b);
};

} // namespace security
