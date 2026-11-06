#include "storage/tar_extract.h"
#include "storage/tree_store.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

// Octal (or GNU base-256) numeric header field. -1 if malformed.
int64_t parseNum(const char* f, size_t len) {
    const unsigned char* u = reinterpret_cast<const unsigned char*>(f);
    if (u[0] & 0x80) {                         // base-256: big sizes / mtimes
        if (u[0] & 0x40) return -1;            // negative: not for us
        int64_t v = u[0] & 0x3f;
        for (size_t i = 1; i < len; i++) {
            if (v > (INT64_MAX >> 8)) return -1;
            v = (v << 8) | u[i];
        }
        return v;
    }
    int64_t v = 0;
    size_t i = 0;
    while (i < len && (f[i] == ' ' || f[i] == '\0')) i++;
    bool any = false;
    for (; i < len && f[i] >= '0' && f[i] <= '7'; i++) {
        if (v > (INT64_MAX >> 3)) return -1;
        v = v * 8 + (f[i] - '0');
        any = true;
    }
    for (; i < len; i++) if (f[i] != ' ' && f[i] != '\0') return -1;
    return any ? v : 0;
}

std::string field(const char* f, size_t len) {
    size_t n = 0;
    while (n < len && f[n]) n++;
    return std::string(f, n);
}

bool allZero(const char* b) {
    for (int i = 0; i < 512; i++) if (b[i]) return false;
    return true;
}

bool checksumOk(const char* h) {
    int64_t want = parseNum(h + 148, 8);
    if (want < 0) return false;
    int64_t sum = 0;
    for (int i = 0; i < 512; i++) sum += (i >= 148 && i < 156) ? ' ' : static_cast<unsigned char>(h[i]);
    return sum == want;
}

int writeAll(int fd, const char* p, size_t n) {
    while (n) {
        ssize_t w = ::write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return errno; }
        p += w; n -= static_cast<size_t>(w);
    }
    return 0;
}

} // namespace

TarStream::TarStream(int rootFd) : root_(rootFd) {}

TarStream::~TarStream() {
    if (out_ >= 0) ::close(out_);
    if (root_ >= 0) ::close(root_);
}

bool TarStream::fail(const std::string& msg) {
    if (st_ != St::Failed) error_ = msg;
    st_ = St::Failed;
    if (out_ >= 0) { ::close(out_); out_ = -1; }
    return false;
}

int TarStream::splitPath(const std::string& path, std::string& parentOut, std::string& nameOut, int& depth) {
    if (path.empty()) return 0;
    if (path[0] == '/') return -1;                              // absolute
    std::vector<std::string> comps;
    size_t i = 0;
    while (i <= path.size()) {
        size_t j = path.find('/', i);
        if (j == std::string::npos) j = path.size();
        std::string c = path.substr(i, j - i);
        i = j + 1;
        if (c.empty() || c == ".") continue;                    // "a//b", "./a", trailing '/'
        if (c == "..") return -1;                               // escape attempt
        if (!TreeStore::validUserName(c)) return 0;             // a name we can't store: skip it
        comps.push_back(std::move(c));
    }
    if (comps.empty()) return 0;
    if (comps.size() > 128) return -1;
    depth = static_cast<int>(comps.size());
    nameOut = comps.back();
    comps.pop_back();
    parentOut.clear();
    for (size_t k = 0; k < comps.size(); k++) { if (k) parentOut += '/'; parentOut += comps[k]; }
    return 1;
}

int TarStream::openParent(const std::string& rel, bool create) {
    int cur = ::dup(root_);
    if (cur < 0) return -1;
    size_t i = 0;
    while (i < rel.size()) {
        size_t j = rel.find('/', i);
        if (j == std::string::npos) j = rel.size();
        const std::string c = rel.substr(i, j - i);
        i = j + 1;
        int next = ::openat(cur, c.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 && errno == ENOENT && create) {
            if (::mkdirat(cur, c.c_str(), 0755) != 0 && errno != EEXIST) { ::close(cur); return -1; }
            next = ::openat(cur, c.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        ::close(cur);
        if (next < 0) return -1;
        cur = next;
    }
    return cur;
}

void TarStream::parsePax(const std::string& recs) {
    // "<len> <key>=<value>\n" records.
    size_t i = 0;
    while (i < recs.size()) {
        size_t sp = recs.find(' ', i);
        if (sp == std::string::npos) return;
        long len = 0;
        try { len = std::stol(recs.substr(i, sp - i)); } catch (...) { return; }
        if (len <= 0 || i + static_cast<size_t>(len) > recs.size()) return;
        std::string rec = recs.substr(sp + 1, i + static_cast<size_t>(len) - sp - 1);
        if (!rec.empty() && rec.back() == '\n') rec.pop_back();
        auto eq = rec.find('=');
        if (eq != std::string::npos) {
            const std::string k = rec.substr(0, eq), v = rec.substr(eq + 1);
            try {
                if (k == "path") nextPath_ = v;
                else if (k == "size") nextSize_ = std::stoll(v);
                else if (k == "mtime") nextMtime_ = std::stoll(v.substr(0, v.find('.')));
            } catch (...) {}
        }
        i += static_cast<size_t>(len);
    }
}

bool TarStream::beginEntry(char type, const std::string& path, int64_t size, int64_t mtime) {
    if (++entries_ > kMaxEntries) return fail("archive has too many entries");
    remaining_ = size;
    pad_ = (512 - (size % 512)) % 512;
    out_ = -1;
    outMtime_ = mtime;

    const bool isFile = (type == '0' || type == '\0' || type == '7');
    const bool isDir = (type == '5');
    if (!isFile && !isDir) { skipped++; st_ = remaining_ ? St::Data : (pad_ ? St::Pad : St::Header); return true; }

    std::string parent, name;
    int depth = 0;
    int ok = splitPath(path, parent, name, depth);
    if (ok < 0) return fail("unsafe path in archive: " + path.substr(0, 200));
    if (ok == 0) { skipped++; st_ = remaining_ ? St::Data : (pad_ ? St::Pad : St::Header); return true; }

    int pfd = openParent(parent, true);
    if (pfd < 0) return fail("cannot create folder for " + path.substr(0, 200) + ": " + std::strerror(errno));
    if (isDir) {
        if (::mkdirat(pfd, name.c_str(), 0755) != 0) {
            struct stat st{};
            if (errno != EEXIST || ::fstatat(pfd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR(st.st_mode)) {
                int e = errno; ::close(pfd);
                return fail("cannot create folder " + path.substr(0, 200) + ": " + std::strerror(e));
            }
        } else {
            dirs++;
        }
        ::close(pfd);
        st_ = remaining_ ? St::Data : (pad_ ? St::Pad : St::Header);
        return true;
    }
    out_ = ::openat(pfd, name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    int e = errno;
    ::close(pfd);
    if (out_ < 0) {
        if (e == EEXIST) return fail("the archive lists " + path.substr(0, 200) + " twice");
        return fail("cannot create " + path.substr(0, 200) + ": " + std::strerror(e));
    }
    files++;
    if (remaining_ == 0) endData();
    else st_ = St::Data;
    return true;
}

void TarStream::endData() {
    if (out_ >= 0) {
        if (outMtime_ > 0) {
            struct timespec ts[2];
            ts[0].tv_sec = ts[1].tv_sec = static_cast<time_t>(outMtime_);
            ts[0].tv_nsec = ts[1].tv_nsec = 0;
            ::futimens(out_, ts);
        }
        ::close(out_);
        out_ = -1;
    }
    st_ = pad_ ? St::Pad : St::Header;
}

bool TarStream::onHeader() {
    if (allZero(hdr_)) {
        if (++zeroBlocks_ >= 2) st_ = St::End;
        return true;
    }
    zeroBlocks_ = 0;
    if (!checksumOk(hdr_)) return fail("not a valid tar archive (bad header checksum)");
    const char type = hdr_[156];
    int64_t size = parseNum(hdr_ + 124, 12);
    int64_t mtime = parseNum(hdr_ + 136, 12);
    if (size < 0) return fail("bad size field in archive");

    if (type == 'L' || type == 'x' || type == 'g') {
        if (size > 1024 * 1024) return fail("archive header too large");
        metaType_ = type;
        meta_.clear();
        remaining_ = size;
        pad_ = (512 - (size % 512)) % 512;
        st_ = size ? St::Meta : (pad_ ? St::Pad : St::Header);
        if (!size) metaType_ = 0;
        return true;
    }

    std::string path;
    if (!nextPath_.empty()) {
        path = nextPath_;
    } else {
        path = field(hdr_, 100);
        if (std::memcmp(hdr_ + 257, "ustar", 5) == 0) {
            std::string prefix = field(hdr_ + 345, 155);
            if (!prefix.empty()) path = prefix + "/" + path;
        }
    }
    if (nextSize_ >= 0) size = nextSize_;
    if (nextMtime_ >= 0) mtime = nextMtime_;
    nextPath_.clear(); nextSize_ = -1; nextMtime_ = -1;
    return beginEntry(type, path, size, mtime);
}

bool TarStream::feed(const char* data, size_t size) {
    while (size > 0) {
        switch (st_) {
        case St::Failed: return false;
        case St::End: return true;               // trailing padding after the end marker
        case St::Header: {
            size_t take = std::min(size, sizeof hdr_ - hdrLen_);
            std::memcpy(hdr_ + hdrLen_, data, take);
            hdrLen_ += take; data += take; size -= take;
            if (hdrLen_ == sizeof hdr_) { hdrLen_ = 0; if (!onHeader()) return false; }
            break;
        }
        case St::Data: {
            size_t take = static_cast<size_t>(std::min<int64_t>(remaining_, static_cast<int64_t>(size)));
            if (out_ >= 0) {
                if (int e = writeAll(out_, data, take)) return fail(std::string("write failed: ") + std::strerror(e));
                bytes += static_cast<int64_t>(take);
            }
            remaining_ -= static_cast<int64_t>(take); data += take; size -= take;
            if (remaining_ == 0) endData();
            break;
        }
        case St::Meta: {
            size_t take = static_cast<size_t>(std::min<int64_t>(remaining_, static_cast<int64_t>(size)));
            meta_.append(data, take);
            remaining_ -= static_cast<int64_t>(take); data += take; size -= take;
            if (remaining_ == 0) {
                if (metaType_ == 'L') { nextPath_ = meta_.substr(0, meta_.find('\0')); }
                else if (metaType_ == 'x') parsePax(meta_);
                metaType_ = 0; meta_.clear();
                st_ = pad_ ? St::Pad : St::Header;
            }
            break;
        }
        case St::Pad: {
            size_t take = static_cast<size_t>(std::min<int64_t>(pad_, static_cast<int64_t>(size)));
            pad_ -= static_cast<int64_t>(take); data += take; size -= take;
            if (pad_ == 0) st_ = St::Header;
            break;
        }
        }
    }
    return st_ != St::Failed;
}

bool TarStream::finish() {
    if (st_ == St::Failed) return false;
    if (st_ == St::End) return true;
    if (st_ == St::Header && hdrLen_ == 0) return true;   // no end marker, but nothing cut off
    return fail("the archive ended in the middle of an entry");
}
