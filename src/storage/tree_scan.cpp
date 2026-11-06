#include "storage/tree_scan.h"
#include "storage/user_lock.h"
#include "routes/events.h"
#include "utils/logger.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <mutex>
#include <thread>

namespace storage {

namespace {
std::atomic<bool> g_rescanNow{false};
std::atomic<bool> g_stop{false};
std::thread g_thread;
extern "C" void onSighup(int) { g_rescanNow.store(true); }
} // namespace

TreeScanResult scanTreeAccount(CloudDB& db, const TreeStore& tree, int64_t userId, const std::string& acct) {
    TreeScanResult r;
    const auto t0 = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lk(userLock(userId));

    std::vector<TreeStore::Entry> found;
    if (!tree.walk(acct, found, r.skipped)) {
        utils::Logger::get_instance().error("tree scan: cannot open account dir '" + acct + "' under " + tree.root());
        return r;
    }
    std::vector<CloudDB::DiskEntry> disk;
    disk.reserve(found.size());
    for (auto& e : found) {
        CloudDB::DiskEntry d;
        d.parent = std::move(e.parent);
        d.name = std::move(e.name);
        d.dir = e.dir;
        d.size = e.size;
        d.mtime = e.mtime;
        if (!d.dir) d.mime = TreeStore::mimeFor(d.name);
        disk.push_back(std::move(d));
    }
    r.ok = db.treeSync(userId, disk, r.stats);
    if (tree.trashDays() > 0) r.trashPurged = tree.purgeTrash(acct);
    r.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    return r;
}

void startTreeScanner(CloudDB& db, const TreeStore& tree, int minutes) {
    if (!tree.enabled()) return;
    // `kill -HUP <pid>` (cloudctl rescan) = scan now instead of waiting for the timer.
    struct sigaction sa{};
    sa.sa_handler = onSighup;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    ::sigaction(SIGHUP, &sa, nullptr);

    if (g_thread.joinable()) return;   // already running
    g_stop.store(false);
    g_thread = std::thread([&db, &tree, minutes]() {
        auto& log = utils::Logger::get_instance();
        while (!g_stop.load()) {
            for (const auto& [uid, acct] : db.treeAccounts()) {
                if (g_stop.load()) return;
                auto r = scanTreeAccount(db, tree, uid, acct);
                if (!r.ok) continue;
                const auto& s = r.stats;
                if (s.changed() || r.trashPurged)
                    log.info("tree scan '" + acct + "': +" + std::to_string(s.foldersAdded) + " folders, +" +
                             std::to_string(s.filesAdded) + " files, ~" + std::to_string(s.filesUpdated) +
                             " updated, -" + std::to_string(s.foldersRemoved) + " folders, -" +
                             std::to_string(s.filesRemoved) + " files, trash purged " + std::to_string(r.trashPurged) +
                             " (" + std::to_string(r.seconds) + " s)");
                if (!r.skipped.empty())
                    log.warn("tree scan '" + acct + "': " + std::to_string(r.skipped.size()) +
                             " entries skipped (first: " + r.skipped.front() + ")");
                if (s.changed()) routes::notifyUser(uid, "files");
            }
            // Wait for the next round, or for SIGHUP.
            const auto until = std::chrono::steady_clock::now() + std::chrono::minutes(minutes > 0 ? minutes : 0);
            while (!g_rescanNow.exchange(false)) {
                if (g_stop.load()) return;
                if (minutes > 0 && std::chrono::steady_clock::now() >= until) break;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    });
}

void stopTreeScanner() {
    g_stop.store(true);
    if (g_thread.joinable()) g_thread.join();
}

} // namespace storage
