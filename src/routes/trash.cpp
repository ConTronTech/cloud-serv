#include "routes/trash.h"
#include "routes/events.h"
#include "routes/tree_helpers.h"
#include "security/request_auth.h"
#include "storage/user_lock.h"

#include <nlohmann/json.hpp>
#include <ctime>
#include <mutex>

using json = nlohmann::json;

// Trash for real-folder accounts (docs/REAL_FOLDERS.md). Deleted items wait in
// <account>/.trash/<YYYY-MM-DD>/ until TRASH_DAYS pass; these routes list them, put them
// back, or remove them for good. An item's id is "<date>:<line in that day's record>".
namespace routes {

namespace {

std::string purgeDate(const std::string& day, int days) {
    std::tm tm{};
    if (strptime(day.c_str(), "%Y-%m-%d", &tm) == nullptr) return "";
    tm.tm_mday += days;
    tm.tm_isdst = -1;
    std::mktime(&tm);
    char buf[16];
    std::strftime(buf, sizeof buf, "%Y-%m-%d", &tm);
    return buf;
}

json itemJson(const TreeStore::TrashItem& it, int trashDays) {
    const auto slash = it.origRel.rfind('/');
    return {{"id", it.date + ":" + std::to_string(it.index)},
            {"name", slash == std::string::npos ? it.origRel : it.origRel.substr(slash + 1)},
            {"from", slash == std::string::npos ? "" : it.origRel.substr(0, slash)},
            {"dir", it.dir}, {"size", it.size}, {"files", it.files},
            {"deletedAt", it.at}, {"purgeOn", purgeDate(it.date, trashDays + 1)}};
}

std::optional<TreeStore::TrashItem> findItem(const TreeStore& tree, const std::string& acct, const std::string& id) {
    for (auto& it : tree.listTrash(acct))
        if (it.date + ":" + std::to_string(it.index) == id) return it;
    return std::nullopt;
}

} // namespace

void registerTrashRoutes(crow::App<http::SecurityMiddleware>& app, CloudDB& db, TreeStore& tree) {

    CROW_ROUTE(app, "/api/trash").methods(crow::HTTPMethod::GET)
    ([&db, &tree](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        auto acct = tree::account(db, tree, *userId);
        if (!acct) return http::jsonError(404, "this account has no trash (deletes are immediate)");
        json items = json::array();
        int64_t bytes = 0;
        auto list = tree.listTrash(*acct);
        for (auto it = list.rbegin(); it != list.rend(); ++it) {   // newest first
            items.push_back(itemJson(*it, tree.trashDays()));
            bytes += it->size;
        }
        return http::jsonSuccess(json{{"items", items}, {"bytes", bytes}, {"trashDays", tree.trashDays()}}.dump());
    });

    // ---- Restore: back to where it was (missing parent folders are recreated) ----
    CROW_ROUTE(app, "/api/trash/restore").methods(crow::HTTPMethod::POST)
    ([&db, &tree](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        auto acct = tree::account(db, tree, *userId);
        if (!acct) return http::jsonError(404, "this account has no trash");
        json body = json::parse(req.body, nullptr, false);
        if (!body.is_object() || !body.contains("id") || !body["id"].is_string()) return http::jsonError(400, "id required");

        std::lock_guard<std::mutex> lk(storage::userLock(*userId));
        auto it = findItem(tree, *acct, body["id"].get<std::string>());
        if (!it) return http::jsonError(404, "not in the trash any more");
        TreeStore::Rel parent; std::string name;
        if (int e = tree.trashRestore(*acct, *it, parent, name)) return tree::fail(e);

        // Index it: find/create the parent folder rows, then the item itself.
        int64_t parentId = 0;
        for (const auto& comp : parent) {
            auto child = db.childFolder(*userId, parentId, comp);
            parentId = child ? *child : db.createFolder(*userId, parentId, comp);
            if (parentId < 0) return http::jsonError(500, "restored on disk but indexing failed; a rescan will fix it");
        }
        int64_t files = 0, folderId = parentId;
        if (it->dir) {
            TreeStore::Rel where = parent; where.push_back(name);
            std::vector<TreeStore::Entry> found; std::vector<std::string> skipped;
            tree.walkAt(*acct, where, found, skipped);
            std::vector<CloudDB::DiskEntry> disk; disk.reserve(found.size());
            for (auto& e : found) disk.push_back(CloudDB::DiskEntry{e.parent, std::move(e.name), e.dir, e.size, e.mtime});
            CloudDB::TreeSyncStats st; int64_t rootId = 0;
            if (!db.treeInsertSubtree(*userId, parentId, name, static_cast<int64_t>(std::time(nullptr)), disk,
                                      TreeStore::mimeFor, rootId, st))
                return http::jsonError(500, "restored on disk but indexing failed; a rescan will fix it");
            files = st.filesAdded; folderId = rootId;
        } else {
            int64_t size = 0;
            if (tree.servePath(*acct, parent, name, &size).empty())
                return http::jsonError(500, "restored on disk but it can't be read; a rescan will fix it");
            if (db.addFile(*userId, parentId, name, TreeStore::mimeFor(name), size, "-", "", "", "", size) < 0)
                return http::jsonError(500, "restored on disk but indexing failed; a rescan will fix it");
            files = 1;
        }
        notifyUser(*userId, "files");
        std::string path;
        for (const auto& c : parent) { path += c; path += '/'; }
        return http::jsonSuccess(json{{"restored", {{"name", name}, {"path", path + name}, {"dir", it->dir},
                                                    {"files", files}, {"folderId", it->dir ? folderId : parentId}}}}.dump());
    });

    // ---- Delete one item for good ----
    CROW_ROUTE(app, "/api/trash/item").methods(crow::HTTPMethod::DELETE)
    ([&db, &tree](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        auto acct = tree::account(db, tree, *userId);
        if (!acct) return http::jsonError(404, "this account has no trash");
        const char* id = req.url_params.get("id");
        if (!id) return http::jsonError(400, "id required");
        std::lock_guard<std::mutex> lk(storage::userLock(*userId));
        auto it = findItem(tree, *acct, id);
        if (!it) return http::jsonError(404, "not in the trash any more");
        if (int e = tree.trashDelete(*acct, *it)) return tree::fail(e);
        notifyUser(*userId, "trash");
        return http::jsonSuccess(R"({"ok":true})");
    });

    // ---- Empty the trash ----
    CROW_ROUTE(app, "/api/trash").methods(crow::HTTPMethod::DELETE)
    ([&db, &tree](const crow::request& req) {
        auto userId = security::authenticateRequest(req, db);
        if (!userId) return http::jsonError(401, "unauthorized");
        auto acct = tree::account(db, tree, *userId);
        if (!acct) return http::jsonError(404, "this account has no trash");
        std::lock_guard<std::mutex> lk(storage::userLock(*userId));
        if (int e = tree.trashEmpty(*acct)) return tree::fail(e);
        notifyUser(*userId, "trash");
        return http::jsonSuccess(R"({"ok":true})");
    });
}

} // namespace routes
