#include "security/crypto.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <stdexcept>

namespace security {

namespace {

std::string toHex(const unsigned char* data, size_t len) {
    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        hex << std::setw(2) << static_cast<int>(data[i]);
    }
    return hex.str();
}

const int kPbkdf2Iters = 200000;   // OWASP-ish for PBKDF2-HMAC-SHA256
const int kSaltBytes = 16;
const int kKeyBytes = 32;

} // namespace

std::string Crypto::randomHex(size_t nbytes) {
    std::vector<unsigned char> buf(nbytes);
    // Prefer OpenSSL's CSPRNG; fall back to /dev/urandom like Auth::generateToken.
    if (RAND_bytes(buf.data(), static_cast<int>(nbytes)) != 1) {
        std::ifstream urandom("/dev/urandom", std::ios::binary);
        urandom.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(nbytes));
        // Fail CLOSED: if both CSPRNG sources fail we must never return the
        // zero-initialized buffer — that would make tokens/keys/salts predictable.
        if (!urandom || static_cast<size_t>(urandom.gcount()) != nbytes) {
            throw std::runtime_error("CSPRNG unavailable — refusing to emit predictable randomness");
        }
    }
    return toHex(buf.data(), nbytes);
}

std::string Crypto::sha256Hex(const std::string& input) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), digest);
    return toHex(digest, SHA256_DIGEST_LENGTH);
}

std::string Crypto::hashPassword(const std::string& password) {
    unsigned char salt[kSaltBytes];
    if (RAND_bytes(salt, kSaltBytes) != 1) {
        std::ifstream urandom("/dev/urandom", std::ios::binary);
        urandom.read(reinterpret_cast<char*>(salt), kSaltBytes);
        if (!urandom || urandom.gcount() != kSaltBytes) {
            throw std::runtime_error("CSPRNG unavailable — refusing to hash with a predictable salt");
        }
    }

    unsigned char out[kKeyBytes];
    PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                      salt, kSaltBytes, kPbkdf2Iters, EVP_sha256(),
                      kKeyBytes, out);

    std::ostringstream stored;
    stored << "pbkdf2$" << kPbkdf2Iters << "$"
           << toHex(salt, kSaltBytes) << "$" << toHex(out, kKeyBytes);
    return stored.str();
}

bool Crypto::verifyPassword(const std::string& password, const std::string& stored) {
    // Parse "pbkdf2$<iters>$<saltHex>$<hashHex>"
    std::vector<std::string> parts;
    std::stringstream ss(stored);
    std::string item;
    while (std::getline(ss, item, '$')) parts.push_back(item);
    if (parts.size() != 4 || parts[0] != "pbkdf2") return false;

    int iters = 0;
    try {
        iters = std::stoi(parts[1]);
    } catch (...) {
        return false;
    }
    if (iters <= 0) return false;

    const std::string& saltHex = parts[2];
    const std::string& hashHex = parts[3];
    if (saltHex.size() % 2 != 0 || hashHex.empty()) return false;

    // Decode salt hex. Guard against malformed (non-hex) stored data: std::stoi
    // throws on bad input, and an unguarded throw here would crash verifyPassword.
    std::vector<unsigned char> salt(saltHex.size() / 2);
    try {
        for (size_t i = 0; i < salt.size(); i++) {
            const std::string byteHex = saltHex.substr(i * 2, 2);
            if (byteHex.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) return false;
            salt[i] = static_cast<unsigned char>(std::stoi(byteHex, nullptr, 16));
        }
    } catch (...) {
        return false;
    }

    size_t keyLen = hashHex.size() / 2;
    std::vector<unsigned char> out(keyLen);
    PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                      salt.data(), static_cast<int>(salt.size()), iters, EVP_sha256(),
                      static_cast<int>(keyLen), out.data());

    return constantTimeEquals(toHex(out.data(), keyLen), hashHex);
}

bool Crypto::constantTimeEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    volatile unsigned char result = 0;
    for (size_t i = 0; i < a.size(); i++) {
        result |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    }
    return result == 0;
}

} // namespace security
