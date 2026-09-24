#include "security/e2e_keys.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <stdexcept>
#include <vector>

namespace security {
namespace e2e {

namespace {

constexpr int kPbkdf2Iterations = 310000;   // CRYPTO_SPEC section 0
constexpr int kSaltLen = 16;
constexpr int kKeyLen = 32;
constexpr int kIvLen = 12;
constexpr int kTagLen = 16;

void randomBytes(unsigned char* out, int n) {
    if (RAND_bytes(out, n) != 1) throw std::runtime_error("RAND_bytes failed");
}

// Standard base64 with '=' padding (NOT URL-safe), no line breaks.
std::string b64(const unsigned char* data, size_t len) {
    std::string out(4 * ((len + 2) / 3) + 1, '\0');
    int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&out[0]), data, static_cast<int>(len));
    if (n < 0) throw std::runtime_error("base64 failed");
    out.resize(static_cast<size_t>(n));
    return out;
}

std::string hexLower(const unsigned char* data, size_t len) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) { s += d[data[i] >> 4]; s += d[data[i] & 0xf]; }
    return s;
}

// wrap(key, plaintext) = b64(iv) + "." + b64(ciphertext || tag)   (AES-256-GCM, aad = empty)
std::string wrap(const unsigned char* key, const unsigned char* plain, int plainLen) {
    unsigned char iv[kIvLen];
    randomBytes(iv, kIvLen);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    std::vector<unsigned char> out(static_cast<size_t>(plainLen) + kTagLen);
    int len = 0, total = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kIvLen, nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) == 1 &&
              EVP_EncryptUpdate(ctx, out.data(), &len, plain, plainLen) == 1;
    if (ok) {
        total = len;
        ok = EVP_EncryptFinal_ex(ctx, out.data() + total, &len) == 1;
        total += len;
    }
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen, out.data() + total) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) throw std::runtime_error("AES-GCM wrap failed");
    return b64(iv, kIvLen) + "." + b64(out.data(), static_cast<size_t>(total) + kTagLen);
}

} // namespace

AccountKeys generateAccountKeys(const std::string& password) {
    AccountKeys k;

    unsigned char salt[kSaltLen];
    randomBytes(salt, kSaltLen);
    k.saltHex = hexLower(salt, kSaltLen);

    // 512 bits: [0:32] auth key (sent to the server), [32:64] KEK (never leaves here).
    std::array<unsigned char, 64> bits{};
    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), salt, kSaltLen,
                          kPbkdf2Iterations, EVP_sha256(), static_cast<int>(bits.size()), bits.data()) != 1)
        throw std::runtime_error("PBKDF2 failed");
    k.authKeyB64 = b64(bits.data(), kKeyLen);
    const unsigned char* kek = bits.data() + kKeyLen;

    unsigned char dek[kKeyLen], rec[kKeyLen];
    try {
        randomBytes(dek, kKeyLen);
        randomBytes(rec, kKeyLen);
        k.wrappedDek = wrap(kek, dek, kKeyLen);
        k.wrappedDekRecovery = wrap(rec, dek, kKeyLen);
        k.recoveryKey = "csr_" + b64(rec, kKeyLen);
    } catch (...) {
        OPENSSL_cleanse(bits.data(), bits.size());
        OPENSSL_cleanse(dek, sizeof dek);
        OPENSSL_cleanse(rec, sizeof rec);
        throw;
    }
    OPENSSL_cleanse(bits.data(), bits.size());
    OPENSSL_cleanse(dek, sizeof dek);
    OPENSSL_cleanse(rec, sizeof rec);
    return k;
}

} // namespace e2e
} // namespace security
