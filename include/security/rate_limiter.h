#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <mutex>

namespace security {

struct ClientBucket {
    size_t tokens;
    std::chrono::steady_clock::time_point last_refill;
    size_t violation_count;
    std::chrono::steady_clock::time_point last_violation;

    ClientBucket() : tokens(0), violation_count(0) {}
};

class RateLimiter {
private:
    std::unordered_map<std::string, ClientBucket> clients_;
    std::mutex mutex_;
    size_t max_tokens_;
    size_t read_refill_rate_;     // tokens/sec for reads
    size_t write_refill_rate_;    // tokens/sec for writes
    size_t ban_threshold_;
    std::chrono::seconds ban_duration_;
    bool enabled_;
    std::vector<std::string> trusted_proxies_;

    void refillTokens(ClientBucket& bucket, size_t refill_rate);
    bool isBanned(const ClientBucket& bucket);

public:
    RateLimiter();

    // Initialize from config values
    void init(bool enable, size_t readRpm, size_t writeRpm,
              size_t burst, size_t banThreshold, int banDurationSec);

    // Set trusted proxy IPs for X-Forwarded-For parsing
    void setTrustedProxies(const std::vector<std::string>& proxies);

    // Check if request is allowed
    bool allowRequest(const std::string& clientIp, bool isWrite = false);

    // Allow / slow down / banned. `credentialed` = the request carries a session or API key:
    // it gets its own bucket and is only ever throttled, never banned, so a logged-in user
    // doing a big upload is slowed down instead of locked out. Anonymous floods still get banned.
    enum class Decision { Allow, Throttle, Banned };
    Decision check(const std::string& clientIp, bool isWrite, bool credentialed);

    // Resolve real client IP from request headers
    // Returns X-Forwarded-For IP if from trusted proxy, otherwise direct IP
    std::string resolveClientIp(const std::string& directIp,
                                 const std::string& forwardedFor) const;

    // Cleanup stale entries (call periodically)
    void cleanupOldClients();

    void setEnabled(bool enable);
};

// Per-account failed-login throttle (keyed by lowercase email), independent of
// the per-IP RateLimiter. Exponential backoff after `freeAttempts` failures.
// Applies equally to unknown emails so it can't be used to enumerate accounts.
class LoginThrottle {
public:
    // Atomically check the lockout and reserve an attempt slot. Returns 0 if the
    // caller may proceed (it MUST then call recordFailure or recordSuccess exactly
    // once), else the seconds to wait (no slot reserved).
    int acquire(const std::string& key);
    void recordFailure(const std::string& key);   // finalizes a reserved slot
    void recordSuccess(const std::string& key);   // finalizes a reserved slot
    // Gives back a reserved slot WITHOUT counting a failure. Only for abnormal exits
    // (an exception between acquire and the finalizer) so a stuck slot can't lock an
    // account out until restart.
    void release(const std::string& key);

private:
    struct Entry {
        int failures = 0;
        int pending = 0;   // reserved, not yet finalized attempts
        std::chrono::steady_clock::time_point lockedUntil;
        std::chrono::steady_clock::time_point last;
    };
    void evictIfOversized(std::chrono::steady_clock::time_point now);
    std::unordered_map<std::string, Entry> entries_;
    std::mutex mutex_;
};

} // namespace security
