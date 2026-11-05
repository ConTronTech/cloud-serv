#pragma once
// "Sign in with authentik" (OpenID Connect, authorization code flow + PKCE).
// The ID token is taken straight from the token endpoint over verified TLS, so (per
// OIDC Core 3.1.3.7 #6) the TLS check stands in for the signature check; we still
// validate iss, aud, exp and the nonce, and read groups from userinfo.
#include <optional>
#include <string>
#include <vector>

namespace security::oidc {

struct Config {
    bool enabled = false;
    std::string issuer, clientId, clientSecret, allowedGroup, label;
    std::vector<std::string> redirectAllow;   // optional OIDC_REDIRECT_URIS allowlist
};

struct Discovery { std::string issuer, authorize, token, userinfo; };

struct Claims {
    std::string sub, email, name, preferredUsername;
    bool emailVerified = false;
    std::vector<std::string> groups;
};

Config loadConfig();                                       // from config.env (OIDC_*)
std::optional<Discovery> discover(const Config& cfg, std::string& err);   // cached after first success
std::string base64url(const std::string& raw);
std::string pkceChallenge(const std::string& verifier);    // base64url(SHA-256(verifier))
std::string urlEncode(const std::string& s);
std::optional<Claims> exchangeCode(const Config& cfg, const Discovery& d, const std::string& code,
                                   const std::string& verifier, const std::string& redirectUri,
                                   const std::string& nonce, std::string& err);

} // namespace security::oidc
