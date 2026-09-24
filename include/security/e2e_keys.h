#pragma once

#include <string>

namespace security {
namespace e2e {

// A complete set of end-to-end key material for a NEW account, generated exactly
// as the browser client does at registration (docs/CRYPTO_SPEC.md section 1) so
// the account can then sign in from the web UI with just its password.
struct AccountKeys {
    std::string saltHex;             // hex(16 random bytes): the PBKDF2 salt, stored server-side
    std::string authKeyB64;          // b64(PBKDF2 bits[0:32]): sent to the server AS the "password"
    std::string wrappedDek;          // wrap(KEK, DEK)                (unlock with the password)
    std::string wrappedDekRecovery;  // wrap(recoveryKey, DEK)        (unlock without the password)
    std::string recoveryKey;         // "csr_" + b64(32 random bytes): shown to the owner ONCE
};

// PBKDF2-HMAC-SHA256 (310000 iterations) of `password` -> 512 bits: [0:32] auth
// key, [32:64] KEK; a random 32-byte DEK; a random 32-byte recovery key. The DEK
// itself is never returned (only wrapped): the server-side tool has no use for it.
// Throws std::runtime_error on any OpenSSL failure. Sensitive buffers are cleansed.
AccountKeys generateAccountKeys(const std::string& password);

} // namespace e2e
} // namespace security
