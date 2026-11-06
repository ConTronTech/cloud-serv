#pragma once

#include "db/database.h"
#include "storage/tree_store.h"

#include <string>
#include <vector>

// Disk -> database sync for real-folder accounts (docs/REAL_FOLDERS.md).
namespace storage {

struct TreeScanResult {
    bool ok = false;
    CloudDB::TreeSyncStats stats;
    std::vector<std::string> skipped;   // entries left out of the index (symlinks, bad names...), printable
    int trashPurged = 0;
    double seconds = 0;
};

// Walk the account's tree, make the index match it, purge old trash.
// Holds the account's storage lock for the duration, so app writes wait.
TreeScanResult scanTreeAccount(CloudDB& db, const TreeStore& tree, int64_t userId, const std::string& acct);

// Background thread: scan every tree account at startup, then every `minutes`
// (0 = startup only). Pushes a live "files" event to the account when anything changed.
void startTreeScanner(CloudDB& db, const TreeStore& tree, int minutes);

} // namespace storage
