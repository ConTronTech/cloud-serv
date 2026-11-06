#include "storage/tree_store.h"
#include "utils/logger.h"
#include "security/crypto.h"

#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// renameat2 / RENAME_NOREPLACE (glibc >= 2.28, needs _GNU_SOURCE which g++ defines).
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif

namespace {

const char* kTempDir = ".cloud-serv";
const char* kTrashDir = ".trash";
const int kMaxDepth = 128;

// Closes an fd on scope exit.
struct Fd {
    int fd = -1;
    Fd() = default;
    explicit Fd(int f) : fd(f) {}
    ~Fd() { if (fd >= 0) ::close(fd); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& o) noexcept : fd(o.fd) { o.fd = -1; }
    Fd& operator=(Fd&& o) noexcept { if (this != &o) { if (fd >= 0) ::close(fd); fd = o.fd; o.fd = -1; } return *this; }
    bool ok() const { return fd >= 0; }
};

bool validUtf8(const std::string& s) {
    size_t i = 0, n = s.size();
    while (i < n) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        int extra;
        uint32_t cp;
        if (c < 0x80) { i++; continue; }
        else if ((c & 0xE0) == 0xC0) { extra = 1; cp = c & 0x1F; if (cp < 2) return false; }   // overlong
        else if ((c & 0xF0) == 0xE0) { extra = 2; cp = c & 0x0F; }
        else if ((c & 0xF8) == 0xF0) { extra = 3; cp = c & 0x07; }
        else return false;
        for (int k = 1; k <= extra; k++) {
            if (i + k >= n) return false;
            unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3F);
        }
        if ((extra == 2 && cp < 0x800) || (extra == 3 && (cp < 0x10000 || cp > 0x10FFFF))) return false;
        if (cp >= 0xD800 && cp <= 0xDFFF) return false;   // surrogates
        i += extra + 1;
    }
    return true;
}

// For logs/reports only: a path that may hold bytes we refused, made printable.
std::string printable(const std::string& s) {
    std::string out;
    for (unsigned char c : s) out += (c < 0x20 || c == 0x7f || c >= 0x80) ? '?' : static_cast<char>(c);
    return out;
}

std::string joinRel(const TreeStore::Rel& rel, const std::string& name) {
    std::string p;
    for (const auto& c : rel) { p += c; p += '/'; }
    return p + name;
}

std::string today() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_r(&t, &tm);
    char buf[16];
    std::strftime(buf, sizeof buf, "%Y-%m-%d", &tm);
    return buf;
}

bool validKey(const std::string& k) {
    if (k.empty() || k.size() > 128) return false;
    for (char c : k) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

// renameat2(NOREPLACE), with a check-then-rename fallback for filesystems without it.
int renameNoReplace(int fromDir, const std::string& from, int toDir, const std::string& to) {
    if (::renameat2(fromDir, from.c_str(), toDir, to.c_str(), RENAME_NOREPLACE) == 0) return 0;
    if (errno != EINVAL && errno != ENOSYS) return errno;
    struct stat st{};
    if (::fstatat(toDir, to.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0) return EEXIST;
    return ::renameat(fromDir, from.c_str(), toDir, to.c_str()) == 0 ? 0 : errno;
}

// Recursively delete `name` inside dirFd without ever following a symlink.
int removeTree(int dirFd, const std::string& name, int depth = 0) {
    struct stat st{};
    if (::fstatat(dirFd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) return errno == ENOENT ? 0 : errno;
    if (!S_ISDIR(st.st_mode)) return ::unlinkat(dirFd, name.c_str(), 0) == 0 ? 0 : errno;
    if (depth > kMaxDepth) return ELOOP;
    int fd = ::openat(dirFd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno;
    DIR* d = ::fdopendir(fd);
    if (!d) { int e = errno; ::close(fd); return e; }
    int err = 0;
    std::vector<std::string> names;
    while (struct dirent* ent = ::readdir(d)) {
        std::string n = ent->d_name;
        if (n == "." || n == "..") continue;
        names.push_back(n);
    }
    for (const auto& n : names) { int e = removeTree(::dirfd(d), n, depth + 1); if (e && !err) err = e; }
    ::closedir(d);   // closes fd
    if (err) return err;
    return ::unlinkat(dirFd, name.c_str(), AT_REMOVEDIR) == 0 ? 0 : errno;
}

int writeAll(int fd, const char* data, size_t size) {
    while (size > 0) {
        ssize_t w = ::write(fd, data, size);
        if (w < 0) { if (errno == EINTR) continue; return errno; }
        data += w; size -= static_cast<size_t>(w);
    }
    return 0;
}

// "photo.jpg" -> "photo (n).jpg"; "archive" -> "archive (n)". Keeps within 255 bytes.
std::string numbered(const std::string& name, int n) {
    std::string base = name, ext;
    auto dot = name.rfind('.');
    if (dot != std::string::npos && dot > 0) { base = name.substr(0, dot); ext = name.substr(dot); }
    std::string suffix = " (" + std::to_string(n) + ")";
    while (base.size() + suffix.size() + ext.size() > 255 && !base.empty()) {
        // Drop exactly one whole UTF-8 character from the end.
        size_t i = base.size() - 1;
        while (i > 0 && (static_cast<unsigned char>(base[i]) & 0xC0) == 0x80) i--;
        base.resize(i);
    }
    return base + suffix + ext;
}

} // namespace

TreeStore::TreeStore(const std::string& root, int trashDays) : root_(root), trashDays_(trashDays < 0 ? 0 : trashDays) {
    while (root_.size() > 1 && root_.back() == '/') root_.pop_back();
}

bool TreeStore::validName(const std::string& name) {
    if (name.empty() || name.size() > 255) return false;
    if (name == "." || name == "..") return false;
    for (unsigned char c : name) {
        if (c < 0x20 || c == 0x7f || c == '/' || c == '\\') return false;
    }
    return validUtf8(name);
}

bool TreeStore::validUserName(const std::string& name) {
    return validName(name) && name != kTempDir && name != kTrashDir;
}

bool TreeStore::validAccountDir(const std::string& dir) {
    if (dir.empty() || dir.size() > 64 || dir[0] == '.') return false;
    for (char c : dir) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '-' || c == '_' || c == '.';
        if (!ok) return false;
    }
    return true;
}

std::string TreeStore::mimeFor(const std::string& name) {
    auto dot = name.rfind('.');
    if (dot == std::string::npos || dot + 1 >= name.size()) return "application/octet-stream";
    std::string ext = name.substr(dot + 1);
    for (auto& ch : ext) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    static const std::pair<const char*, const char*> map[] = {
        {"jpg", "image/jpeg"}, {"jpeg", "image/jpeg"}, {"png", "image/png"}, {"gif", "image/gif"},
        {"webp", "image/webp"}, {"avif", "image/avif"}, {"bmp", "image/bmp"}, {"svg", "image/svg+xml"},
        {"heic", "image/heic"}, {"tif", "image/tiff"}, {"tiff", "image/tiff"}, {"ico", "image/x-icon"},
        {"mp4", "video/mp4"}, {"m4v", "video/mp4"}, {"webm", "video/webm"}, {"mkv", "video/x-matroska"},
        {"mov", "video/quicktime"}, {"avi", "video/x-msvideo"}, {"ts", "video/mp2t"},
        {"mp3", "audio/mpeg"}, {"m4a", "audio/mp4"}, {"aac", "audio/aac"}, {"flac", "audio/flac"},
        {"wav", "audio/wav"}, {"ogg", "audio/ogg"}, {"opus", "audio/opus"},
        {"pdf", "application/pdf"}, {"txt", "text/plain"}, {"md", "text/markdown"}, {"log", "text/plain"},
        {"csv", "text/csv"}, {"json", "application/json"}, {"xml", "application/xml"}, {"html", "text/html"},
        {"htm", "text/html"}, {"zip", "application/zip"}, {"7z", "application/x-7z-compressed"},
        {"rar", "application/vnd.rar"}, {"gz", "application/gzip"}, {"tar", "application/x-tar"},
        {"xz", "application/x-xz"}, {"zst", "application/zstd"}, {"iso", "application/x-iso9660-image"},
        {"doc", "application/msword"}, {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {"xls", "application/vnd.ms-excel"}, {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
        {"ppt", "application/vnd.ms-powerpoint"}, {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
        {"odt", "application/vnd.oasis.opendocument.text"}, {"epub", "application/epub+zip"},
        {"blend", "application/x-blender"}, {"stl", "model/stl"}, {"obj", "model/obj"}, {"glb", "model/gltf-binary"},
        {"gltf", "model/gltf+json"},
    };
    for (const auto& [e, m] : map) if (ext == e) return m;
    return "application/octet-stream";
}

int TreeStore::openAccount(const std::string& acct) const {
    if (!enabled() || !validAccountDir(acct)) { errno = EINVAL; return -1; }
    Fd root(::open(root_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (!root.ok()) return -1;
    return ::openat(root.fd, acct.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

int TreeStore::openDirAt(int base, const Rel& rel, bool create) const {
    if (rel.size() > static_cast<size_t>(kMaxDepth)) { errno = ELOOP; return -1; }
    int cur = ::dup(base);
    if (cur < 0) return -1;
    for (const auto& comp : rel) {
        if (!validName(comp)) { ::close(cur); errno = EINVAL; return -1; }
        int next = ::openat(cur, comp.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 && errno == ENOENT && create) {
            if (::mkdirat(cur, comp.c_str(), 0755) != 0 && errno != EEXIST) { int e = errno; ::close(cur); errno = e; return -1; }
            next = ::openat(cur, comp.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        int e = errno;
        ::close(cur);
        if (next < 0) { errno = (e == ELOOP) ? ENOTDIR : e; return -1; }   // ELOOP = it was a symlink
        cur = next;
    }
    return cur;
}

bool TreeStore::ensureAccount(const std::string& acct) const {
    if (!enabled() || !validAccountDir(acct)) return false;
    Fd root(::open(root_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (!root.ok()) {
        utils::Logger::get_instance().error("TreeStore: cannot open TREE_ROOT " + root_ + ": " + std::strerror(errno));
        return false;
    }
    if (::mkdirat(root.fd, acct.c_str(), 0700) != 0 && errno != EEXIST) return false;
    Fd a(::openat(root.fd, acct.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    return a.ok();
}

int TreeStore::makeDir(const std::string& acct, const Rel& parent, const std::string& name) const {
    if (!validUserName(name)) return EINVAL;
    Fd a(openAccount(acct)); if (!a.ok()) return errno;
    Fd p(openDirAt(a.fd, parent, false)); if (!p.ok()) return errno;
    return ::mkdirat(p.fd, name.c_str(), 0755) == 0 ? 0 : errno;
}

int TreeStore::rename(const std::string& acct, const Rel& fromParent, const std::string& fromName,
                      const Rel& toParent, const std::string& toName) const {
    if (!validUserName(fromName) || !validUserName(toName)) return EINVAL;
    Fd a(openAccount(acct)); if (!a.ok()) return errno;
    Fd from(openDirAt(a.fd, fromParent, false)); if (!from.ok()) return errno;
    Fd to(openDirAt(a.fd, toParent, false)); if (!to.ok()) return errno;
    if (fromParent == toParent && fromName == toName) return 0;
    return renameNoReplace(from.fd, fromName, to.fd, toName);
}

namespace { const char* kTrashLog = ".cloud-serv-trash.jsonl"; }

int TreeStore::trash(const std::string& acct, const Rel& parent, const std::string& name,
                     int64_t size, int64_t files) const {
    if (!validUserName(name)) return EINVAL;
    Fd a(openAccount(acct)); if (!a.ok()) return errno;
    Fd p(openDirAt(a.fd, parent, false)); if (!p.ok()) return errno;
    struct stat st{};
    if (::fstatat(p.fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) return errno;
    if (trashDays_ == 0) return removeTree(p.fd, name);

    Rel where{kTrashDir, today()};
    where.insert(where.end(), parent.begin(), parent.end());
    Fd t(openDirAt(a.fd, where, true)); if (!t.ok()) return errno;
    std::string placed = name;
    int e = renameNoReplace(p.fd, name, t.fd, placed);
    for (int n = 1; e == EEXIST && n < 1000; n++) { placed = numbered(name, n); e = renameNoReplace(p.fd, name, t.fd, placed); }
    if (e) return e;

    // Record it (append-only; a failure here only hides the item from the Trash view).
    Fd day(openDirAt(a.fd, Rel{kTrashDir, today()}, false));
    if (day.ok()) {
        nlohmann::json j = {{"t", joinRel(parent, placed)}, {"o", joinRel(parent, name)}, {"d", S_ISDIR(st.st_mode)},
                            {"s", size > 0 ? size : (S_ISDIR(st.st_mode) ? 0 : static_cast<int64_t>(st.st_size))},
                            {"n", files > 0 ? files : (S_ISDIR(st.st_mode) ? 0 : 1)},
                            {"at", static_cast<int64_t>(std::time(nullptr))}};
        const std::string line = j.dump() + "\n";
        Fd log(::openat(day.fd, kTrashLog, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (log.ok()) writeAll(log.fd, line.data(), line.size());
    }
    return 0;
}

namespace {
bool isDayDir(const std::string& n) {
    return n.size() == 10 && n[4] == '-' && n[7] == '-' &&
           std::all_of(n.begin(), n.end(), [](char c) { return (c >= '0' && c <= '9') || c == '-'; });
}
TreeStore::Rel splitRel(const std::string& s) {
    TreeStore::Rel r; std::string cur;
    for (char c : s) { if (c == '/') { if (!cur.empty()) r.push_back(cur); cur.clear(); } else cur += c; }
    if (!cur.empty()) r.push_back(cur);
    return r;
}
} // namespace

std::vector<TreeStore::TrashItem> TreeStore::listTrash(const std::string& acct) const {
    std::vector<TrashItem> out;
    Fd a(openAccount(acct)); if (!a.ok()) return out;
    Fd t(::openat(a.fd, kTrashDir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)); if (!t.ok()) return out;
    int d = ::dup(t.fd); DIR* dir = d >= 0 ? ::fdopendir(d) : nullptr;
    if (!dir) { if (d >= 0) ::close(d); return out; }
    std::vector<std::string> days;
    while (struct dirent* ent = ::readdir(dir)) if (isDayDir(ent->d_name)) days.push_back(ent->d_name);
    ::closedir(dir);
    std::sort(days.begin(), days.end());
    for (const auto& day : days) {
        Fd dd(::openat(t.fd, day.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)); if (!dd.ok()) continue;
        Fd lf(::openat(dd.fd, kTrashLog, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)); if (!lf.ok()) continue;
        std::string text; char buf[65536]; ssize_t r;
        while ((r = ::read(lf.fd, buf, sizeof buf)) > 0) text.append(buf, static_cast<size_t>(r));
        std::istringstream in(text); std::string line; int idx = -1;
        while (std::getline(in, line)) {
            idx++;
            auto j = nlohmann::json::parse(line, nullptr, false);
            if (j.is_discarded() || !j.is_object() || !j.contains("t") || !j.contains("o")) continue;
            TrashItem it;
            it.date = day; it.index = idx;
            it.trashRel = j.value("t", ""); it.origRel = j.value("o", "");
            it.dir = j.value("d", false); it.size = j.value("s", int64_t(0)); it.files = j.value("n", int64_t(0));
            it.at = j.value("at", int64_t(0));
            Rel tr = splitRel(it.trashRel);
            if (tr.empty() || splitRel(it.origRel).empty()) continue;
            // Still there? (restored or deleted-forever items are simply gone)
            std::string leaf = tr.back(); tr.pop_back();
            Fd parent(openDirAt(dd.fd, tr, false)); if (!parent.ok()) continue;
            struct stat st{};
            if (::fstatat(parent.fd, leaf.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) continue;
            if (S_ISDIR(st.st_mode) != it.dir) continue;
            out.push_back(std::move(it));
        }
    }
    return out;
}

int TreeStore::trashRestore(const std::string& acct, const TrashItem& it, Rel& parentOut, std::string& nameOut) const {
    if (!isDayDir(it.date)) return EINVAL;
    Rel tr = splitRel(it.trashRel), orig = splitRel(it.origRel);
    if (tr.empty() || orig.empty()) return EINVAL;
    for (const auto& c : orig) if (!validUserName(c)) return EINVAL;
    Fd a(openAccount(acct)); if (!a.ok()) return errno;
    Rel srcParent{kTrashDir, it.date}; srcParent.insert(srcParent.end(), tr.begin(), tr.end() - 1);
    Fd src(openDirAt(a.fd, srcParent, false)); if (!src.ok()) return errno;
    const std::string want = orig.back();
    Rel dstParent(orig.begin(), orig.end() - 1);
    Fd dst(openDirAt(a.fd, dstParent, true)); if (!dst.ok()) return errno;   // recreate missing parents
    std::string cand = want;
    int e = renameNoReplace(src.fd, tr.back(), dst.fd, cand);
    for (int n = 1; e == EEXIST && n < 1000; n++) { cand = numbered(want, n); e = renameNoReplace(src.fd, tr.back(), dst.fd, cand); }
    if (e) return e;
    parentOut = dstParent; nameOut = cand;
    return 0;
}

int TreeStore::trashDelete(const std::string& acct, const TrashItem& it) const {
    if (!isDayDir(it.date)) return EINVAL;
    Rel tr = splitRel(it.trashRel); if (tr.empty()) return EINVAL;
    Fd a(openAccount(acct)); if (!a.ok()) return errno;
    Rel parent{kTrashDir, it.date}; parent.insert(parent.end(), tr.begin(), tr.end() - 1);
    Fd p(openDirAt(a.fd, parent, false)); if (!p.ok()) return errno;
    return removeTree(p.fd, tr.back());
}

int TreeStore::trashEmpty(const std::string& acct) const {
    Fd a(openAccount(acct)); if (!a.ok()) return errno;
    Fd t(::openat(a.fd, kTrashDir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (!t.ok()) return errno == ENOENT ? 0 : errno;
    int d = ::dup(t.fd); DIR* dir = d >= 0 ? ::fdopendir(d) : nullptr;
    if (!dir) { if (d >= 0) ::close(d); return errno; }
    std::vector<std::string> days;
    while (struct dirent* ent = ::readdir(dir)) if (isDayDir(ent->d_name)) days.push_back(ent->d_name);
    ::closedir(dir);
    int err = 0;
    for (const auto& day : days) if (int e = removeTree(t.fd, day)) err = e;
    return err;
}

int TreeStore::ensureTempDir(int acctFd) const {
    return openDirAt(acctFd, Rel{kTempDir, "uploads"}, true);
}

int TreeStore::tempCreate(const std::string& acct, const std::string& key) const {
    if (!validKey(key)) return EINVAL;
    Fd a(openAccount(acct)); if (!a.ok()) return errno;
    Fd t(ensureTempDir(a.fd)); if (!t.ok()) return errno;
    Fd f(::openat(t.fd, key.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644));
    return f.ok() ? 0 : errno;
}

int TreeStore::tempAppend(const std::string& acct, const std::string& key, const char* data, size_t size) const {
    if (!validKey(key)) return EINVAL;
    Fd a(openAccount(acct)); if (!a.ok()) return errno;
    Fd t(ensureTempDir(a.fd)); if (!t.ok()) return errno;
    Fd f(::openat(t.fd, key.c_str(), O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC));
    if (!f.ok()) return errno;
    return writeAll(f.fd, data, size);
}

int64_t TreeStore::tempSize(const std::string& acct, const std::string& key) const {
    if (!validKey(key)) return -1;
    Fd a(openAccount(acct)); if (!a.ok()) return -1;
    Fd t(ensureTempDir(a.fd)); if (!t.ok()) return -1;
    struct stat st{};
    if (::fstatat(t.fd, key.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode)) return -1;
    return static_cast<int64_t>(st.st_size);
}

void TreeStore::tempRemove(const std::string& acct, const std::string& key) const {
    if (!validKey(key)) return;
    Fd a(openAccount(acct)); if (!a.ok()) return;
    Fd t(ensureTempDir(a.fd)); if (!t.ok()) return;
    ::unlinkat(t.fd, key.c_str(), 0);
}

int TreeStore::tempPlace(const std::string& acct, const std::string& key, const Rel& parent,
                         const std::string& name, bool autoRename, std::string& finalName) const {
    if (!validKey(key) || !validUserName(name)) return EINVAL;
    Fd a(openAccount(acct)); if (!a.ok()) return errno;
    Fd t(ensureTempDir(a.fd)); if (!t.ok()) return errno;
    Fd p(openDirAt(a.fd, parent, false)); if (!p.ok()) return errno;
    std::string cand = name;
    int e = renameNoReplace(t.fd, key, p.fd, cand);
    for (int n = 1; autoRename && e == EEXIST && n < 1000; n++) {
        cand = numbered(name, n);
        e = renameNoReplace(t.fd, key, p.fd, cand);
    }
    if (e == 0) finalName = cand;
    return e;
}

int TreeStore::writeFile(const std::string& acct, const Rel& parent, const std::string& name,
                         const char* data, size_t size, bool autoRename, std::string& finalName) const {
    const std::string key = security::Crypto::randomHex(16);
    int e = tempCreate(acct, key);
    if (!e && size) e = tempAppend(acct, key, data, size);
    if (!e) e = tempPlace(acct, key, parent, name, autoRename, finalName);
    if (e) tempRemove(acct, key);
    return e;
}

std::string TreeStore::servePath(const std::string& acct, const Rel& parent, const std::string& name,
                                 int64_t* sizeOut) const {
    if (!validUserName(name)) return "";
    Fd a(openAccount(acct)); if (!a.ok()) return "";
    Fd p(openDirAt(a.fd, parent, false)); if (!p.ok()) return "";
    Fd f(::openat(p.fd, name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
    if (!f.ok()) return "";
    struct stat viaFd{};
    if (::fstat(f.fd, &viaFd) != 0 || !S_ISREG(viaFd.st_mode)) return "";
    // The path we hand to the HTTP layer must name this exact file: a component swapped
    // for a symlink between our walk and now would show up as a different inode.
    std::string path = root_ + "/" + acct + "/" + joinRel(parent, name);
    struct stat viaPath{};
    if (::lstat(path.c_str(), &viaPath) != 0 || viaPath.st_dev != viaFd.st_dev || viaPath.st_ino != viaFd.st_ino)
        return "";
    if (sizeOut) *sizeOut = static_cast<int64_t>(viaFd.st_size);
    return path;
}

namespace {
void walkDir(int dirFd, const TreeStore::Rel& rel, int32_t selfIdx, std::vector<TreeStore::Entry>& out,
             std::vector<std::string>& skipped, int depth) {
    if (depth > kMaxDepth) { skipped.push_back(printable(joinRel(rel, "")) + " (too deep)"); return; }
    int fd = ::dup(dirFd);
    if (fd < 0) return;
    DIR* d = ::fdopendir(fd);
    if (!d) { ::close(fd); return; }
    std::vector<std::string> names;
    while (struct dirent* ent = ::readdir(d)) {
        std::string n = ent->d_name;
        if (n == "." || n == "..") continue;
        if (rel.empty() && (n == kTempDir || n == kTrashDir)) continue;
        names.push_back(n);
    }
    ::closedir(d);
    for (const auto& n : names) {
        struct stat st{};
        if (::fstatat(dirFd, n.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) continue;
        const bool isDir = S_ISDIR(st.st_mode), isReg = S_ISREG(st.st_mode);
        if (!isDir && !isReg) {
            if (S_ISLNK(st.st_mode)) skipped.push_back(printable(joinRel(rel, n)) + " (symlink)");
            continue;
        }
        if (!TreeStore::validUserName(n)) {
            skipped.push_back(printable(joinRel(rel, n)) + " (name not allowed)");
            continue;
        }
        TreeStore::Entry e;
        e.parent = selfIdx; e.name = n; e.dir = isDir;
        e.size = isReg ? static_cast<int64_t>(st.st_size) : 0;
        e.mtime = static_cast<int64_t>(st.st_mtime);
        const int32_t myIdx = static_cast<int32_t>(out.size());
        out.push_back(std::move(e));
        if (isDir) {
            int sub = ::openat(dirFd, n.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (sub < 0) { skipped.push_back(printable(joinRel(rel, n)) + " (cannot open)"); continue; }
            TreeStore::Rel child = rel; child.push_back(n);
            walkDir(sub, child, myIdx, out, skipped, depth + 1);
            ::close(sub);
        }
    }
}
} // namespace

bool TreeStore::walk(const std::string& acct, std::vector<Entry>& out, std::vector<std::string>& skipped) const {
    Fd a(openAccount(acct));
    if (!a.ok()) return false;
    walkDir(a.fd, Rel{}, -1, out, skipped, 0);
    return true;
}

int TreeStore::purgeTrash(const std::string& acct) const {
    Fd a(openAccount(acct)); if (!a.ok()) return 0;
    Fd t(::openat(a.fd, kTrashDir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (!t.ok()) return 0;
    std::time_t cutoff = std::time(nullptr) - static_cast<std::time_t>(trashDays_) * 86400;
    std::tm cut{};
    localtime_r(&cutoff, &cut);
    char cutBuf[16];
    std::strftime(cutBuf, sizeof cutBuf, "%Y-%m-%d", &cut);
    const std::string cutStr = cutBuf;

    int dup = ::dup(t.fd);
    DIR* d = dup >= 0 ? ::fdopendir(dup) : nullptr;
    if (!d) { if (dup >= 0) ::close(dup); return 0; }
    std::vector<std::string> old;
    while (struct dirent* ent = ::readdir(d)) {
        std::string n = ent->d_name;
        // Only our own YYYY-MM-DD folders; anything else in .trash is left alone.
        if (n.size() != 10 || n[4] != '-' || n[7] != '-') continue;
        if (n < cutStr) old.push_back(n);
    }
    ::closedir(d);
    int purged = 0;
    for (const auto& n : old) if (removeTree(t.fd, n) == 0) purged++;
    return purged;
}

// ---- folder uploads: staging + placement ----

int TreeStore::extractRoot(const std::string& acct, const std::string& key, bool create) const {
    if (!validKey(key)) { errno = EINVAL; return -1; }
    Fd a(openAccount(acct)); if (!a.ok()) return -1;
    Fd x(openDirAt(a.fd, Rel{kTempDir, "extract"}, true)); if (!x.ok()) return -1;
    if (create && ::mkdirat(x.fd, key.c_str(), 0755) != 0 && errno != EEXIST) return -1;
    return ::openat(x.fd, key.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

int TreeStore::extractPlace(const std::string& acct, const std::string& key, const Rel& parent,
                            const std::string& name, std::string& finalName) const {
    if (!validKey(key) || !validUserName(name)) return EINVAL;
    Fd a(openAccount(acct)); if (!a.ok()) return errno;
    Fd x(openDirAt(a.fd, Rel{kTempDir, "extract"}, false)); if (!x.ok()) return errno;
    Fd p(openDirAt(a.fd, parent, false)); if (!p.ok()) return errno;
    std::string cand = name;
    int e = renameNoReplace(x.fd, key, p.fd, cand);
    for (int n = 1; e == EEXIST && n < 1000; n++) { cand = numbered(name, n); e = renameNoReplace(x.fd, key, p.fd, cand); }
    if (e == 0) finalName = cand;
    return e;
}

void TreeStore::extractRemove(const std::string& acct, const std::string& key) const {
    if (!validKey(key)) return;
    Fd a(openAccount(acct)); if (!a.ok()) return;
    Fd x(openDirAt(a.fd, Rel{kTempDir, "extract"}, false)); if (!x.ok()) return;
    removeTree(x.fd, key);
}

bool TreeStore::walkAt(const std::string& acct, const Rel& start, std::vector<Entry>& out,
                       std::vector<std::string>& skipped) const {
    Fd a(openAccount(acct)); if (!a.ok()) return false;
    Fd d(openDirAt(a.fd, start, false)); if (!d.ok()) return false;
    walkDir(d.fd, start, -1, out, skipped, static_cast<int>(start.size()));
    return true;
}
