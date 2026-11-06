#pragma once
// One mutex per user. Quota checks and the writes they guard run under it, so
// parallel uploads from one account can't all pass "is there room?" at once.
#include <cstdint>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace storage {
inline std::mutex& userLock(int64_t userId) {
    static std::mutex guard;
    static std::unordered_map<int64_t, std::unique_ptr<std::mutex>> locks;
    std::lock_guard<std::mutex> lk(guard);
    auto& m = locks[userId];
    if (!m) m = std::make_unique<std::mutex>();
    return *m;
}
} // namespace storage
