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

    // Resolve real client IP from request headers
    // Returns X-Forwarded-For IP if from trusted proxy, otherwise direct IP
    std::string resolveClientIp(const std::string& directIp,
                                 const std::string& forwardedFor) const;

    // Cleanup stale entries (call periodically)
    void cleanupOldClients();

    // Get token count for monitoring
    size_t getClientTokens(const std::string& clientIp);

    // Reset a specific client
    void resetClient(const std::string& clientIp);

    void setEnabled(bool enable);
};

} // namespace security
