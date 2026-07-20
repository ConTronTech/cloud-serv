#include "security/rate_limiter.h"
#include "utils/logger.h"
#include "utils/string_utils.h"
#include <algorithm>

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

std::string RateLimiter::resolveClientIp(const std::string& directIp,
                                          const std::string& forwardedFor) const {
    // If no forwarded header or no trusted proxies, use direct IP
    if (forwardedFor.empty() || trusted_proxies_.empty()) {
        return directIp;
    }

    // Check if direct connection is from a trusted proxy
    bool fromTrustedProxy = false;
    for (const auto& proxy : trusted_proxies_) {
        if (directIp == proxy) {
            fromTrustedProxy = true;
            break;
        }
    }

    if (!fromTrustedProxy) {
        // Direct IP is not a trusted proxy — ignore X-Forwarded-For
        // (could be spoofed by the client)
        return directIp;
    }

    // Parse X-Forwarded-For: client, proxy1, proxy2
    // The leftmost non-trusted IP is the real client
    auto parts = utils::StringUtils::split(forwardedFor, ',');
    for (auto& part : parts) {
        std::string ip = utils::StringUtils::trim(part);
        if (ip.empty()) continue;

        // Check if this IP is also a trusted proxy
        bool isTrusted = false;
        for (const auto& proxy : trusted_proxies_) {
            if (ip == proxy) {
                isTrusted = true;
                break;
            }
        }

        if (!isTrusted) {
            // This is the real client IP
            return ip;
        }
    }

    // All IPs in chain are trusted proxies — use the first one
    if (!parts.empty()) {
        return utils::StringUtils::trim(parts[0]);
    }

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

size_t RateLimiter::getClientTokens(const std::string& clientIp) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = clients_.find(clientIp);
    if (it == clients_.end()) return max_tokens_;

    ClientBucket bucket = it->second;
    refillTokens(bucket, read_refill_rate_);
    return bucket.tokens;
}

void RateLimiter::resetClient(const std::string& clientIp) {
    std::lock_guard<std::mutex> lock(mutex_);
    clients_.erase(clientIp);
    utils::Logger::get_instance().info("Reset rate limit: " + clientIp);
}

} // namespace security
