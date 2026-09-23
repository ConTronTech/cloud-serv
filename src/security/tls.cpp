#include "security/tls.h"
#include "utils/logger.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/objects.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <memory>
#include <filesystem>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace security {
namespace tls {

namespace {

template <typename T, void (*F)(T*)>
struct Deleter { void operator()(T* p) const { if (p) F(p); } };
using PkeyPtr = std::unique_ptr<EVP_PKEY, Deleter<EVP_PKEY, EVP_PKEY_free>>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, Deleter<EVP_PKEY_CTX, EVP_PKEY_CTX_free>>;
using X509Ptr = std::unique_ptr<X509, Deleter<X509, X509_free>>;

[[noreturn]] void fail(const std::string& what) {
    unsigned long e = ERR_get_error();
    char buf[256] = {0};
    if (e) ERR_error_string_n(e, buf, sizeof(buf));
    throw std::runtime_error("TLS: " + what + (e ? std::string(" (") + buf + ")" : ""));
}

bool inCgnat(const in_addr& a) {
    uint32_t h = ntohl(a.s_addr);
    return (h & 0xFFC00000u) == 0x64400000u;  // 100.64.0.0/10
}

std::vector<std::string> localIPv4s() {
    std::vector<std::string> out;
    struct ifaddrs* ifs = nullptr;
    if (getifaddrs(&ifs) != 0) return out;
    for (auto* i = ifs; i; i = i->ifa_next) {
        if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
        char buf[INET_ADDRSTRLEN];
        auto* sin = reinterpret_cast<sockaddr_in*>(i->ifa_addr);
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) out.push_back(buf);
    }
    freeifaddrs(ifs);
    return out;
}

bool validIPv4(const std::string& s) {
    in_addr a;
    return inet_pton(AF_INET, s.c_str(), &a) == 1;
}

std::string san_string(const std::string& tsIp) {
    std::set<std::string> ips{"127.0.0.1"};
    for (auto& ip : localIPv4s()) ips.insert(ip);
    if (!tsIp.empty()) ips.insert(tsIp);
    std::string san = "DNS:localhost";
    for (auto& ip : ips) san += ",IP:" + ip;
    return san;
}

// True if the cert at cert_path parses and its SAN covers ip.
bool certCoversIp(const std::string& cert_path, const std::string& ip) {
    FILE* f = fopen(cert_path.c_str(), "r");
    if (!f) return false;
    X509Ptr x(PEM_read_X509(f, nullptr, nullptr, nullptr));
    fclose(f);
    if (!x) return false;
    if (ip.empty()) return true;
    return X509_check_ip_asc(x.get(), ip.c_str(), 0) == 1;
}

void generate(const std::string& cert_path, const std::string& key_path, const std::string& tsIp) {
    // EC P-256 key
    PkeyCtxPtr kctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!kctx || EVP_PKEY_keygen_init(kctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx.get(), NID_X9_62_prime256v1) <= 0)
        fail("EC keygen init failed");
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(kctx.get(), &raw) <= 0) fail("EC keygen failed");
    PkeyPtr pkey(raw);

    X509Ptr x(X509_new());
    if (!x) fail("X509_new failed");
    X509_set_version(x.get(), 2);

    unsigned char serial[16];
    if (RAND_bytes(serial, sizeof(serial)) != 1) fail("RAND_bytes failed");
    serial[0] &= 0x7F;  // positive
    BIGNUM* bn = BN_bin2bn(serial, sizeof(serial), nullptr);
    if (!bn) fail("serial alloc failed");
    BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x.get()));
    BN_free(bn);

    X509_gmtime_adj(X509_getm_notBefore(x.get()), -60 * 60);           // 1h clock-skew slack
    X509_gmtime_adj(X509_getm_notAfter(x.get()), 60L * 60 * 24 * 3650); // 10 years
    X509_set_pubkey(x.get(), pkey.get());

    X509_NAME* name = X509_get_subject_name(x.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("cloud-serv"), -1, -1, 0);
    X509_set_issuer_name(x.get(), name);

    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x.get(), x.get(), nullptr, nullptr, 0);
    struct Ext { int nid; std::string val; };
    for (const Ext& e : {Ext{NID_subject_alt_name, san_string(tsIp)},
                         Ext{NID_basic_constraints, "critical,CA:FALSE"},
                         Ext{NID_key_usage, "critical,digitalSignature"},
                         Ext{NID_ext_key_usage, "serverAuth"}}) {
        X509_EXTENSION* ex = X509V3_EXT_conf_nid(nullptr, &ctx, e.nid, e.val.c_str());
        if (!ex) fail("extension build failed: " + e.val);
        X509_add_ext(x.get(), ex, -1);
        X509_EXTENSION_free(ex);
    }

    if (!X509_sign(x.get(), pkey.get(), EVP_sha256())) fail("X509_sign failed");

    // Parent dirs first (0700), same owner-only idiom as the data directory.
    for (const auto& p : {cert_path, key_path}) {
        std::filesystem::path parent = std::filesystem::path(p).parent_path();
        if (parent.empty()) continue;
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
    }
    {
        std::filesystem::path kp = std::filesystem::path(key_path).parent_path();
        if (!kp.empty()) ::chmod(kp.c_str(), S_IRWXU);
    }

    // Key: created 0600 from the start (no world-readable window).
    int fd = ::open(key_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) fail("cannot write key file " + key_path);
    FILE* kf = fdopen(fd, "w");
    if (!kf) { ::close(fd); fail("fdopen key file failed"); }
    ::fchmod(fd, 0600);  // in case the file pre-existed with looser perms
    bool ok = PEM_write_PrivateKey(kf, pkey.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1;
    fclose(kf);
    if (!ok) fail("writing key failed");
    ::chmod(key_path.c_str(), 0600);

    FILE* cf = fopen(cert_path.c_str(), "w");
    if (!cf) fail("cannot write cert file " + cert_path);
    ok = PEM_write_X509(cf, x.get()) == 1;
    fclose(cf);
    if (!ok) fail("writing cert failed");
    ::chmod(cert_path.c_str(), 0644);
}

} // namespace

std::string detect_tailscale_ip() {
    if (FILE* p = popen("tailscale ip -4 2>/dev/null", "r")) {
        char line[128] = {0};
        std::string out;
        if (fgets(line, sizeof(line), p)) out = line;
        int rc = pclose(p);
        while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' '))
            out.pop_back();
        if (rc == 0 && validIPv4(out)) return out;
    }
    for (auto& ip : localIPv4s()) {
        in_addr a;
        if (inet_pton(AF_INET, ip.c_str(), &a) == 1 && inCgnat(a)) return ip;
    }
    return "";
}

bool ensure_server_cert(const std::string& cert_path, const std::string& key_path) {
    auto& log = utils::Logger::get_instance();
    std::string tsIp = detect_tailscale_ip();

    bool haveFiles = std::filesystem::exists(cert_path) && std::filesystem::exists(key_path);
    if (haveFiles && certCoversIp(cert_path, tsIp)) {
        // Keep permissions tight on an existing key too.
        ::chmod(key_path.c_str(), 0600);
        std::filesystem::path kp = std::filesystem::path(key_path).parent_path();
        if (!kp.empty()) ::chmod(kp.c_str(), S_IRWXU);
        return false;
    }

    if (haveFiles)
        log.info("TLS: existing cert does not cover Tailscale IP " + tsIp + " (or is unreadable) — regenerating");
    else
        log.info("TLS: generating self-signed certificate at " + cert_path);
    generate(cert_path, key_path, tsIp);
    log.info("TLS: certificate SAN = " + san_string(tsIp));
    return true;
}

} // namespace tls
} // namespace security
