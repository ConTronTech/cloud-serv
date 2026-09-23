#include "security/rate_limiter.h"
#include "utils/logger.h"
#include "utils/string_utils.h"
#include <algorithm>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>

namespace security {

RateLimiter::RateLimiter()
    : max_tokens_(15)
    , read_refill_rate_(2)
    , write_refill_rate_(1)
    , ban_threshold_(10)
    , ban_duration_(600)
    , enabled_(true) {
}

void RateLimiter::init(bool enable, size_t readRpm, size_t writeRpm,
                       size_t burst, size_t banThreshold, int banDurationSec) {
    std::lock_guard<std::mutex> lock(mutex_);

    enabled_ = enable;
    max_tokens_ = burst;
    read_refill_rate_ = readRpm / 60;
    write_refill_rate_ = writeRpm / 60;
    if (read_refill_rate_ == 0) read_refill_rate_ = 1;
    if (write_refill_rate_ == 0) write_refill_rate_ = 1;
    ban_threshold_ = banThreshold;
    ban_duration_ = std::chrono::seconds(banDurationSec);

    utils::Logger::get_instance().info("Rate limiter: read=" +
        std::to_string(readRpm) + "rpm, write=" +
        std::to_string(writeRpm) + "rpm, burst=" +
        std::to_string(burst) + ", enabled=" + (enable ? "true" : "false"));
}

void RateLimiter::setTrustedProxies(const std::vector<std::string>& proxies) {
    trusted_proxies_ = proxies;
    utils::Logger::get_instance().info("Trusted proxies: " +
        std::to_string(proxies.size()) + " configured");
}

void RateLimiter::setEnabled(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    enabled_ = enable;
}

void RateLimiter::refillTokens(ClientBucket& bucket, size_t refill_rate) {
    auto now = std::chrono::steady_clock::now();

    if (bucket.last_refill.time_since_epoch().count() == 0) {
        bucket.last_refill = now;
        bucket.tokens = max_tokens_;
        return;
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - bucket.last_refill);

    if (elapsed.count() > 0) {
        size_t tokens_to_add = elapsed.count() * refill_rate;
        bucket.tokens = std::min(bucket.tokens + tokens_to_add, max_tokens_);
        bucket.last_refill = now;
    }
}

bool RateLimiter::isBanned(const ClientBucket& bucket) {
    if (bucket.violation_count < ban_threshold_) {
        return false;
    }

    auto now = std::chrono::steady_clock::now();
    auto since_violation = std::chrono::duration_cast<std::chrono::seconds>(
        now - bucket.last_violation);

    return since_violation < ban_duration_;
}

bool RateLimiter::allowRequest(const std::string& clientIp, bool isWrite) {
    if (!enabled_) return true;

    std::lock_guard<std::mutex> lock(mutex_);

    ClientBucket& bucket = clients_[clientIp];

    // Check ban
    if (isBanned(bucket)) {
        utils::Logger::get_instance().warn("Banned client: " + clientIp);
        return false;
    }

    // Refill with appropriate rate
    size_t rate = isWrite ? write_refill_rate_ : read_refill_rate_;
    refillTokens(bucket, rate);

    // Check tokens
    if (bucket.tokens > 0) {
        bucket.tokens--;
        return true;
    }

    // Rate limited
    bucket.violation_count++;
    bucket.last_violation = std::chrono::steady_clock::now();

    utils::Logger::get_instance().warn("Rate limited: " + clientIp +
        " (violations: " + std::to_string(bucket.violation_count) +
        ", write=" + (isWrite ? "true" : "false") + ")");

    return false;
}

// Validate an IP literal and canonicalize it. IPv6 loopback and IPv4-mapped
// forms collapse to their IPv4 equivalents so they match TRUSTED_PROXIES.
// Returns "" if the token is not an IP literal.
static std::string normalizeIp(const std::string& s) {
    in_addr a4{};
    if (inet_pton(AF_INET, s.c_str(), &a4) == 1) {
        char buf[INET_ADDRSTRLEN];
        return inet_ntop(AF_INET, &a4, buf, sizeof buf) ? buf : "";
    }
    in6_addr a6{};
    if (inet_pton(AF_INET6, s.c_str(), &a6) == 1) {
        static const unsigned char mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        static const unsigned char zeros[15] = {0};
        if (std::memcmp(a6.s6_addr, zeros, 15) == 0 && a6.s6_addr[15] == 1) return "127.0.0.1";
        if (std::memcmp(a6.s6_addr, mapped, 12) == 0) {
            char buf[INET_ADDRSTRLEN];
            return inet_ntop(AF_INET, a6.s6_addr + 12, buf, sizeof buf) ? buf : "";
        }
        char buf[INET6_ADDRSTRLEN];
        return inet_ntop(AF_INET6, &a6, buf, sizeof buf) ? buf : "";
    }
    return "";
}

std::string RateLimiter::resolveClientIp(const std::string& directIp,
                                          const std::string& forwardedFor) const {
    // If no forwarded header or no trusted proxies, use direct IP
    if (forwardedFor.empty() || trusted_proxies_.empty()) {
        return directIp;
    }

    auto isTrusted = [this](const std::string& ip) {
        for (const auto& proxy : trusted_proxies_) {
            std::string np = normalizeIp(proxy);
            if (ip == (np.empty() ? proxy : np)) return true;
        }
        return false;
    };

    std::string direct = normalizeIp(directIp);
    if (direct.empty()) direct = directIp;

    // Direct peer must be a trusted proxy, else X-Forwarded-For is client-controlled.
    if (!isTrusted(direct)) return directIp;

    // Proxies APPEND to X-Forwarded-For, so the left side is client-supplied.
    // Walk right-to-left, skipping trusted hops; the rightmost untrusted,
    // valid IP literal is the address our trusted proxy actually saw.
    auto parts = utils::StringUtils::split(forwardedFor, ',');
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
        std::string tok = utils::StringUtils::trim(*it);
        if (tok.empty()) continue;
        std::string ip = normalizeIp(tok);
        if (ip.empty()) return directIp;   // garbage in the chain: don't trust it
        if (isTrusted(ip)) continue;
        return ip;
    }

    // Entire chain is trusted proxies.
    return directIp;
}

void RateLimiter::cleanupOldClients() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::steady_clock::now();
    const auto threshold = std::chrono::minutes(30);

    for (auto it = clients_.begin(); it != clients_.end();) {
        auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(
            now - it->second.last_refill);

        if (elapsed > threshold) {
            it = clients_.erase(it);
        } else {
            ++it;
        }
    }
}

namespace {
constexpr int kFree = 5;            // failures before any lockout
constexpr int kMaxLockSec = 900;    // 15 min cap
constexpr size_t kMaxEntries = 10000;
}

// Bound memory without ever bulk-clearing: drop stale entries, then evict
// least-recently-used ones, sparing locked / in-flight entries unless nothing
// else remains.
void LoginThrottle::evictIfOversized(std::chrono::steady_clock::time_point now) {
    if (entries_.size() <= kMaxEntries) return;
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (it->second.pending == 0 && now - it->second.last > std::chrono::hours(1)) it = entries_.erase(it);
        else ++it;
    }
    while (entries_.size() > kMaxEntries) {
        auto victim = entries_.end();
        bool victimProtected = true;
        for (auto it = entries_.begin(); it != entries_.end(); ++it) {
            bool prot = it->second.pending > 0 || it->second.lockedUntil > now;
            if (victim == entries_.end() ||
                (victimProtected && !prot) ||
                (prot == victimProtected && it->second.last < victim->second.last)) {
                victim = it;
                victimProtected = prot;
            }
        }
        if (victim == entries_.end()) break;
        entries_.erase(victim);
    }
}

int LoginThrottle::acquire(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    auto it = entries_.find(key);
    if (it == entries_.end()) {
        evictIfOversized(now);
        it = entries_.emplace(key, Entry{}).first;
        it->second.last = now;
    }
    Entry& e = it->second;
    if (e.pending == 0 && now - e.last > std::chrono::hours(1)) e.failures = 0;
    if (e.lockedUntil > now) {
        return static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(
            e.lockedUntil - now).count()) + 1;
    }
    // In-flight attempts count as potential failures, so concurrent callers can't
    // collectively exceed the free budget; past it, attempts are serialized.
    if (e.pending >= std::max(1, kFree - e.failures)) return 1;
    e.pending++;
    return 0;
}

void LoginThrottle::recordFailure(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    auto& e = entries_[key];
    if (e.pending > 0) e.pending--;
    e.last = now;
    e.failures++;
    if (e.failures >= kFree) {
        int shift = std::min(e.failures - kFree, 10);
        int lock = std::min(30 * (1 << shift), kMaxLockSec);   // 30s, 60s, 120s ...
        e.lockedUntil = now + std::chrono::seconds(lock);
    }
}

void LoginThrottle::recordSuccess(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.erase(key);
}

void LoginThrottle::release(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(key);
    if (it != entries_.end() && it->second.pending > 0) it->second.pending--;
}

} // namespace security
