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
#include <ctime>
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

// Usable existing cert: parses, not expiring within 24h, and either covers the
// Tailscale IP or is NOT self-signed. A Tailscale/Let's Encrypt cert only has
// the DNS name in its SAN (never the IP), so a non-self-signed cert must be
// preserved — otherwise a transient tailscaled failure at boot would overwrite
// a trusted cert with a self-signed one.
bool certUsable(const std::string& cert_path, const std::string& ip) {
    FILE* f = fopen(cert_path.c_str(), "r");
    if (!f) return false;
    X509Ptr x(PEM_read_X509(f, nullptr, nullptr, nullptr));
    fclose(f);
    if (!x) return false;
    time_t soon = time(nullptr) + 24 * 3600;
    if (X509_cmp_time(X509_get0_notAfter(x.get()), &soon) <= 0) return false;
    if (ip.empty() || X509_check_ip_asc(x.get(), ip.c_str(), 0) == 1) return true;
    return X509_check_issued(x.get(), x.get()) != X509_V_OK;  // not self-signed
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

// Runs a command via popen and captures stdout. NOTE: popen goes through a shell,
// which is acceptable here ONLY because every argument is derived from tailscale's
// own output or operator-owned config (TLS_CERT_PATH/TLS_KEY_PATH), never from
// attacker-reachable input; paths are additionally single-quote escaped.
bool runCapture(const std::string& cmd, std::string& out, int* rcOut = nullptr) {
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return false;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), p)) > 0 && out.size() < (1u << 20)) out.append(buf, n);
    int rc = pclose(p);
    if (rcOut) *rcOut = rc;
    return rc == 0;
}

std::string shQuote(const std::string& s) {
    std::string r = "'";
    for (char c : s) { if (c == '\'') r += "'\\''"; else r += c; }
    return r + "'";
}

bool validHostname(const std::string& h) {
    if (h.empty() || h.size() > 253) return false;
    for (char c : h)
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.')) return false;
    return h.find('.') != std::string::npos;
}

// This box's MagicDNS name (e.g. host.tailnet.ts.net) from `tailscale status --json`
// -> Self.DNSName. Empty if tailscale is missing, logged out, or MagicDNS is off.
std::string detect_tailscale_hostname() {
    std::string out;
    if (!runCapture("tailscale status --json 2>/dev/null", out)) return "";
    size_t self = out.find("\"Self\"");
    if (self == std::string::npos) return "";
    size_t k = out.find("\"DNSName\"", self);
    if (k == std::string::npos) return "";
    size_t q1 = out.find('"', out.find(':', k) + 1);
    if (q1 == std::string::npos) return "";
    size_t q2 = out.find('"', q1 + 1);
    if (q2 == std::string::npos) return "";
    std::string h = out.substr(q1 + 1, q2 - q1 - 1);
    while (!h.empty() && h.back() == '.') h.pop_back();
    for (auto& c : h) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return validHostname(h) ? h : "";
}

// Preferred path: real Tailscale-issued cert. Returns true if cert/key are in place.
bool tryTailscaleCert(const std::string& cert_path, const std::string& key_path) {
    auto& log = utils::Logger::get_instance();
    std::string host = detect_tailscale_hostname();
    if (host.empty()) {
        log.warn("TLS: no Tailscale MagicDNS name available (tailscale missing/logged out/MagicDNS off) — falling back to self-signed");
        return false;
    }
    for (const auto& p : {cert_path, key_path}) {
        std::filesystem::path parent = std::filesystem::path(p).parent_path();
        if (parent.empty()) continue;
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
    }
    std::filesystem::path kp = std::filesystem::path(key_path).parent_path();
    if (!kp.empty()) ::chmod(kp.c_str(), S_IRWXU);

    std::string cmd = "tailscale cert --cert-file " + shQuote(cert_path) + " --key-file " +
                      shQuote(key_path) + " " + shQuote(host) + " 2>&1";
    std::string out;
    int rc = -1;
    if (!runCapture(cmd, out, &rc) || !std::filesystem::exists(cert_path) ||
        !std::filesystem::exists(key_path)) {
        while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
        log.warn("TLS: `tailscale cert " + host + "` failed (" + out.substr(0, 300) +
                 ") — falling back to self-signed");
        return false;
    }
    ::chmod(key_path.c_str(), 0600);
    ::chmod(cert_path.c_str(), 0644);
    log.info("TLS: using Tailscale-issued certificate for " + host);
    return true;
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

bool ensure_server_cert(const std::string& cert_path, const std::string& key_path,
                        bool preferTailscaleCert) {
    auto& log = utils::Logger::get_instance();
    if (preferTailscaleCert && tryTailscaleCert(cert_path, key_path)) return true;
    std::string tsIp = detect_tailscale_ip();

    bool haveFiles = std::filesystem::exists(cert_path) && std::filesystem::exists(key_path);
    if (haveFiles && certUsable(cert_path, tsIp)) {
        // Keep permissions tight on an existing key too.
        ::chmod(key_path.c_str(), 0600);
        std::filesystem::path kp = std::filesystem::path(key_path).parent_path();
        if (!kp.empty()) ::chmod(kp.c_str(), S_IRWXU);
        return false;
    }

    if (haveFiles)
        log.info("TLS: existing cert is unusable (expired/unreadable or self-signed without Tailscale IP " + tsIp + ") — regenerating");
    else
        log.info("TLS: generating self-signed certificate at " + cert_path);
    generate(cert_path, key_path, tsIp);
    log.info("TLS: certificate SAN = " + san_string(tsIp));
    return true;
}

} // namespace tls
} // namespace security
