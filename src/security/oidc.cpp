#include "security/oidc.h"
#include "core/config.h"
#include "utils/logger.h"

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cctype>
#include <ctime>
#include <mutex>

using json = nlohmann::json;

namespace security::oidc {
namespace {

struct HttpResult { long status = 0; std::string body; std::string error; };

size_t collect(char* p, size_t s, size_t n, void* ud) {
    auto* out = static_cast<std::string*>(ud);
    if (out->size() + s * n > 1024 * 1024) return 0;      // 1 MB cap on IdP responses
    out->append(p, s * n);
    return s * n;
}

// Small libcurl wrapper: TLS verified against the system CAs, short timeouts, no redirects.
HttpResult http(const std::string& url, const std::string* postBody,
                const std::string* basicUser, const std::string* basicPass, const std::string* bearer) {
    HttpResult r;
    CURL* c = curl_easy_init();
    if (!c) { r.error = "curl init failed"; return r; }
    struct curl_slist* hdrs = nullptr;
    hdrs = curl_slist_append(hdrs, "Accept: application/json");
    std::string auth;
    if (bearer) { auth = "Authorization: Bearer " + *bearer; hdrs = curl_slist_append(hdrs, auth.c_str()); }
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, collect);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &r.body);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(c, CURLOPT_PROTOCOLS_STR, "https,http");
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    if (postBody) {
        curl_easy_setopt(c, CURLOPT_POST, 1L);
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, postBody->c_str());
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, static_cast<long>(postBody->size()));
    }
    if (basicUser && basicPass) {
        curl_easy_setopt(c, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(c, CURLOPT_USERNAME, basicUser->c_str());
        curl_easy_setopt(c, CURLOPT_PASSWORD, basicPass->c_str());
    }
    CURLcode rc = curl_easy_perform(c);
    if (rc != CURLE_OK) r.error = curl_easy_strerror(rc);
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &r.status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(c);
    return r;
}

std::string b64urlDecode(std::string s) {
    for (auto& ch : s) { if (ch == '-') ch = '+'; else if (ch == '_') ch = '/'; }
    while (s.size() % 4) s += '=';
    std::string out(s.size(), '\0');
    int n = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                            reinterpret_cast<const unsigned char*>(s.data()), static_cast<int>(s.size()));
    if (n < 0) return "";
    size_t pad = 0; while (pad < 2 && !s.empty() && s[s.size() - 1 - pad] == '=') pad++;
    out.resize(static_cast<size_t>(n) - pad);
    return out;
}

std::string strOf(const json& j, const char* k) { auto it = j.find(k); return (it != j.end() && it->is_string()) ? it->get<std::string>() : ""; }

std::mutex discMx;
std::optional<Discovery> discCache;

} // namespace

Config loadConfig() {
    auto& c = core::Config::get_instance();
    Config cfg;
    cfg.issuer = c.get("env", "OIDC_ISSUER", "");
    cfg.clientId = c.get("env", "OIDC_CLIENT_ID", "");
    cfg.clientSecret = c.get("env", "OIDC_CLIENT_SECRET", "");
    cfg.allowedGroup = c.get("env", "OIDC_ALLOWED_GROUP", "");
    cfg.label = c.get("env", "OIDC_BUTTON_LABEL", "SSO");
    std::string allow = c.get("env", "OIDC_REDIRECT_URIS", "");
    size_t a = 0;
    while (a < allow.size()) {
        size_t b = allow.find(',', a); if (b == std::string::npos) b = allow.size();
        std::string u = allow.substr(a, b - a);
        while (!u.empty() && u.front() == ' ') u.erase(0, 1);
        while (!u.empty() && u.back() == ' ') u.pop_back();
        if (!u.empty()) cfg.redirectAllow.push_back(u);
        a = b + 1;
    }
    cfg.enabled = !cfg.issuer.empty() && !cfg.clientId.empty() && !cfg.clientSecret.empty();
    return cfg;
}

std::optional<Discovery> discover(const Config& cfg, std::string& err) {
    std::lock_guard<std::mutex> lk(discMx);
    if (discCache) return discCache;
    std::string base = cfg.issuer;
    if (!base.empty() && base.back() != '/') base += '/';
    HttpResult r = http(base + ".well-known/openid-configuration", nullptr, nullptr, nullptr, nullptr);
    if (!r.error.empty() || r.status != 200) { err = "discovery failed: " + (r.error.empty() ? std::to_string(r.status) : r.error); return std::nullopt; }
    json j = json::parse(r.body, nullptr, false);
    if (!j.is_object()) { err = "discovery: bad json"; return std::nullopt; }
    Discovery d{strOf(j, "issuer"), strOf(j, "authorization_endpoint"), strOf(j, "token_endpoint"), strOf(j, "userinfo_endpoint")};
    if (d.issuer.empty() || d.authorize.empty() || d.token.empty()) { err = "discovery: missing endpoints"; return std::nullopt; }
    discCache = d;
    return d;
}

std::string base64url(const std::string& raw) {
    std::string out(4 * ((raw.size() + 2) / 3) + 1, '\0');
    int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                            reinterpret_cast<const unsigned char*>(raw.data()), static_cast<int>(raw.size()));
    out.resize(static_cast<size_t>(n));
    for (auto& ch : out) { if (ch == '+') ch = '-'; else if (ch == '/') ch = '_'; }
    while (!out.empty() && out.back() == '=') out.pop_back();
    return out;
}

std::string pkceChallenge(const std::string& verifier) {
    unsigned char h[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(verifier.data()), verifier.size(), h);
    return base64url(std::string(reinterpret_cast<char*>(h), sizeof h));
}

std::string urlEncode(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string o;
    for (unsigned char ch : s) {
        if (std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~') o += static_cast<char>(ch);
        else { o += '%'; o += hex[ch >> 4]; o += hex[ch & 15]; }
    }
    return o;
}

std::optional<Claims> exchangeCode(const Config& cfg, const Discovery& d, const std::string& code,
                                   const std::string& verifier, const std::string& redirectUri,
                                   const std::string& nonce, std::string& err) {
    std::string body = "grant_type=authorization_code&code=" + urlEncode(code) +
                       "&redirect_uri=" + urlEncode(redirectUri) + "&code_verifier=" + urlEncode(verifier);
    HttpResult r = http(d.token, &body, &cfg.clientId, &cfg.clientSecret, nullptr);
    if (!r.error.empty() || r.status != 200) { err = "token exchange failed: " + (r.error.empty() ? std::to_string(r.status) : r.error); return std::nullopt; }
    json tok = json::parse(r.body, nullptr, false);
    std::string idToken = tok.is_object() ? strOf(tok, "id_token") : "";
    std::string access = tok.is_object() ? strOf(tok, "access_token") : "";
    if (idToken.empty()) { err = "no id_token"; return std::nullopt; }

    size_t p1 = idToken.find('.'), p2 = idToken.find('.', p1 == std::string::npos ? 0 : p1 + 1);
    if (p1 == std::string::npos || p2 == std::string::npos) { err = "malformed id_token"; return std::nullopt; }
    json c = json::parse(b64urlDecode(idToken.substr(p1 + 1, p2 - p1 - 1)), nullptr, false);
    if (!c.is_object()) { err = "unreadable id_token"; return std::nullopt; }

    // iss / aud / exp / nonce
    if (strOf(c, "iss") != d.issuer) { err = "issuer mismatch"; return std::nullopt; }
    bool audOk = false;
    if (c.contains("aud")) {
        if (c["aud"].is_string()) audOk = c["aud"].get<std::string>() == cfg.clientId;
        else if (c["aud"].is_array()) for (auto& a : c["aud"]) if (a.is_string() && a.get<std::string>() == cfg.clientId) audOk = true;
    }
    if (!audOk) { err = "audience mismatch"; return std::nullopt; }
    const int64_t now = static_cast<int64_t>(::time(nullptr));
    if (!c.contains("exp") || !c["exp"].is_number() || c["exp"].get<int64_t>() + 60 < now) { err = "id_token expired"; return std::nullopt; }
    if (strOf(c, "nonce") != nonce || nonce.empty()) { err = "nonce mismatch"; return std::nullopt; }

    Claims out;
    out.sub = strOf(c, "sub");
    out.email = strOf(c, "email");
    out.name = strOf(c, "name");
    out.preferredUsername = strOf(c, "preferred_username");
    out.emailVerified = c.contains("email_verified") && c["email_verified"].is_boolean() && c["email_verified"].get<bool>();
    auto takeGroups = [&](const json& j) {
        if (j.contains("groups") && j["groups"].is_array())
            for (auto& g : j["groups"]) if (g.is_string()) out.groups.push_back(g.get<std::string>());
    };
    takeGroups(c);
    // userinfo is authoritative for profile/groups (same TLS-verified channel)
    if (!d.userinfo.empty() && !access.empty()) {
        HttpResult u = http(d.userinfo, nullptr, nullptr, nullptr, &access);
        json ui = (u.error.empty() && u.status == 200) ? json::parse(u.body, nullptr, false) : json();
        if (ui.is_object() && strOf(ui, "sub") == out.sub) {
            if (out.email.empty()) out.email = strOf(ui, "email");
            if (out.name.empty()) out.name = strOf(ui, "name");
            if (out.preferredUsername.empty()) out.preferredUsername = strOf(ui, "preferred_username");
            if (out.groups.empty()) takeGroups(ui);
        }
    }
    if (out.sub.empty()) { err = "no subject"; return std::nullopt; }
    return out;
}

} // namespace security::oidc
