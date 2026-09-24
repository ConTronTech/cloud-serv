#include "storage/file_store.h"
#include "utils/logger.h"

#include <filesystem>
#include <fstream>

#include <sys/stat.h>

namespace fs = std::filesystem;

FileStore::FileStore(const std::string& baseDir) : baseDir_(baseDir) {
    std::error_code ec;
    fs::create_directories(baseDir_, ec);
    if (ec) {
        utils::Logger::get_instance().error("FileStore: cannot create " + baseDir_ +
                                            ": " + ec.message());
    }
}

namespace {
// Storage keys are always server-generated hex (Crypto::randomHex). Enforce that
// invariant here as defense-in-depth: a key is only ever a bare filename, so it
// can never contain a path separator or ".." that would escape the user's dir.
bool isSafeKey(const std::string& key) {
    if (key.empty() || key.size() > 128) return false;
    for (char c : key) {
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return true;
}
} // namespace

std::string FileStore::userDir(int64_t userId) const {
    return baseDir_ + "/" + std::to_string(userId);
}

std::string FileStore::pathFor(int64_t userId, const std::string& storageKey) const {
    return userDir(userId) + "/" + storageKey;
}

bool FileStore::write(int64_t userId, const std::string& storageKey,
                      const char* data, size_t size) const {
    if (!isSafeKey(storageKey)) return false;
    std::error_code ec;
    fs::create_directories(userDir(userId), ec);
    if (ec) {
        utils::Logger::get_instance().error("FileStore::write mkdir: " + ec.message());
        return false;
    }
    ::chmod(userDir(userId).c_str(), S_IRWXU);  // owner-only, not the ambient umask

    std::ofstream out(pathFor(userId, storageKey), std::ios::binary | std::ios::trunc);
    if (!out) return false;
    if (size > 0) out.write(data, static_cast<std::streamsize>(size));
    out.close();
    ::chmod(pathFor(userId, storageKey).c_str(), 0600);
    return !out.fail();
}

bool FileStore::append(int64_t userId, const std::string& storageKey,
                       const char* data, size_t size) const {
    if (!isSafeKey(storageKey)) return false;
    std::error_code ec;
    fs::create_directories(userDir(userId), ec);
    if (ec) {
        utils::Logger::get_instance().error("FileStore::append mkdir: " + ec.message());
        return false;
    }
    ::chmod(userDir(userId).c_str(), S_IRWXU);  // owner-only, not the ambient umask
    std::ofstream out(pathFor(userId, storageKey), std::ios::binary | std::ios::app);
    if (!out) return false;
    if (size > 0) out.write(data, static_cast<std::streamsize>(size));
    out.close();
    ::chmod(pathFor(userId, storageKey).c_str(), 0600);
    return !out.fail();
}

int64_t FileStore::sizeOf(int64_t userId, const std::string& storageKey) const {
    if (!isSafeKey(storageKey)) return -1;
    std::error_code ec;
    auto n = fs::file_size(pathFor(userId, storageKey), ec);
    if (ec) return -1;
    return static_cast<int64_t>(n);
}

bool FileStore::remove(int64_t userId, const std::string& storageKey) const {
    if (!isSafeKey(storageKey)) return false;
    std::error_code ec;
    fs::remove(pathFor(userId, storageKey), ec);
    return !ec;
}

bool FileStore::stageUserDir(int64_t userId, const std::string& destDir) const {
    std::error_code ec;
    fs::create_directories(destDir, ec);
    if (ec) {
        utils::Logger::get_instance().error("FileStore::stageUserDir mkdir: " + ec.message());
        return false;
    }
    ::chmod(destDir.c_str(), S_IRWXU);

    const fs::path src = userDir(userId);
    if (!fs::exists(src, ec)) return true;  // nothing stored for this user

    for (const auto& entry : fs::directory_iterator(src, ec)) {
        std::error_code e2;
        // Blobs are flat regular files. Never follow or replicate anything else
        // (symlinks, subdirectories) into the backup.
        if (!entry.is_regular_file(e2) || entry.is_symlink(e2)) continue;
        const fs::path dst = fs::path(destDir) / entry.path().filename();
        fs::create_hard_link(entry.path(), dst, e2);
        if (e2) {
            e2.clear();
            fs::copy_file(entry.path(), dst, fs::copy_options::none, e2);
            if (e2) {
                utils::Logger::get_instance().error("FileStore::stageUserDir copy " +
                                                    entry.path().filename().string() + ": " + e2.message());
                return false;
            }
            ::chmod(dst.c_str(), 0600);
        }
    }
    if (ec) {
        utils::Logger::get_instance().error("FileStore::stageUserDir iterate: " + ec.message());
        return false;
    }
    return true;
}

bool FileStore::removeUserDir(int64_t userId) const {
    std::error_code ec;
    fs::remove_all(userDir(userId), ec);
    if (ec) {
        utils::Logger::get_instance().error("FileStore::removeUserDir: " + ec.message());
        return false;
    }
    return true;
}
