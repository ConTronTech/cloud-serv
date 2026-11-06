#pragma once

#include <cstdint>
#include <string>
#include <vector>

// TreeStore — "real folders" storage for unencrypted accounts (docs/REAL_FOLDERS.md).
//
// An account's files live as a normal folder tree under <TREE_ROOT>/<account dir>/.
// The database is only an index of that tree; the tree is the truth.
//
// Safety: nothing here builds an absolute path and hands it to open(). Every access
// starts from an fd of the account root and walks one validated name at a time with
// O_NOFOLLOW, so a symlink anywhere in the tree (or planted later) is never followed
// out of it. Names are validated before they reach any syscall.
//
// Reserved at the account root: .cloud-serv/ (upload temp space) and .trash/.
class TreeStore {
public:
    using Rel = std::vector<std::string>;   // folder path below the account root, root-first

    explicit TreeStore(const std::string& root, int trashDays = 30);
    bool enabled() const { return !root_.empty(); }
    const std::string& root() const { return root_; }
    int trashDays() const { return trashDays_; }

    // A single path component that may exist in the tree: non-empty, <= 255 bytes,
    // valid UTF-8, no '/', '\\', NUL or control chars, not "." / "..".
    static bool validName(const std::string& name);
    // validName + not one of the reserved root entries.
    static bool validUserName(const std::string& name);
    // An account directory name (letters, digits, - _ .), not starting with '.'.
    static bool validAccountDir(const std::string& dir);
    // Best-guess MIME type from the file extension (files found on disk have no Content-Type).
    static std::string mimeFor(const std::string& name);

    // Create <root>/<acct> (0700) if missing. false if it can't be made or isn't a dir.
    bool ensureAccount(const std::string& acct) const;

    // All of these return 0 on success or an errno value.
    int makeDir(const std::string& acct, const Rel& parent, const std::string& name) const;
    // Rename/move one entry. Never replaces an existing target (EEXIST).
    int rename(const std::string& acct, const Rel& fromParent, const std::string& fromName,
               const Rel& toParent, const std::string& toName) const;
    // Delete = move into .trash/<YYYY-MM-DD>/<parent path>/<name> (or unlink when trashDays==0).
    int trash(const std::string& acct, const Rel& parent, const std::string& name) const;

    // Upload temp space (<acct>/.cloud-serv/uploads/<key>), same filesystem as the tree.
    int tempCreate(const std::string& acct, const std::string& key) const;
    int tempAppend(const std::string& acct, const std::string& key, const char* data, size_t size) const;
    int64_t tempSize(const std::string& acct, const std::string& key) const;   // -1 if missing
    void tempRemove(const std::string& acct, const std::string& key) const;
    // Move a finished temp file into the tree. If `name` is taken and autoRename is set,
    // tries "name (1).ext", "name (2).ext"...; finalName gets the name actually used.
    int tempPlace(const std::string& acct, const std::string& key, const Rel& parent,
                  const std::string& name, bool autoRename, std::string& finalName) const;
    // One-shot write of a whole file (temp + place).
    int writeFile(const std::string& acct, const Rel& parent, const std::string& name,
                  const char* data, size_t size, bool autoRename, std::string& finalName) const;

    // Verify a file can be served (every component walked with O_NOFOLLOW, final entry a
    // regular file) and return its absolute path + current size. Empty string if not.
    std::string servePath(const std::string& acct, const Rel& parent, const std::string& name,
                          int64_t* sizeOut = nullptr) const;

    // Walk the whole account tree (no symlinks, no special files, reserved dirs skipped).
    // `parent` = index (in the walk's output) of the folder this entry is in; -1 = account root.
    // Folders are always listed before anything inside them. Kept compact on purpose:
    // a real tree has ~1M entries, so no per-entry path copies.
    struct Entry { int32_t parent = -1; std::string name; bool dir = false; int64_t size = 0; int64_t mtime = 0; };
    bool walk(const std::string& acct, std::vector<Entry>& out,
              std::vector<std::string>& skipped) const;

    // Remove .trash/<date>/ folders older than trashDays. Returns how many were purged.
    int purgeTrash(const std::string& acct) const;

private:
    std::string root_;
    int trashDays_;

    int openAccount(const std::string& acct) const;              // fd or -1 (errno set)
    int openDirAt(int base, const Rel& rel, bool create) const;   // fd or -1 (errno set)
    int ensureTempDir(int acctFd) const;                          // fd of .cloud-serv/uploads or -1
};
