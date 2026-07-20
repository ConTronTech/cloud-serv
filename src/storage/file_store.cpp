#include "storage/file_store.h"
#include "utils/logger.h"

#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

FileStore::FileStore(const std::string& baseDir) : baseDir_(baseDir) {
    std::error_code ec;
    fs::create_directories(baseDir_, ec);
    if (ec) {
        utils::Logger::get_instance().error("FileStore: cannot create " + baseDir_ +
                                            ": " + ec.message());
    }
}

std::string FileStore::userDir(int64_t userId) const {
    return baseDir_ + "/" + std::to_string(userId);
}

std::string FileStore::pathFor(int64_t userId, const std::string& storageKey) const {
    return userDir(userId) + "/" + storageKey;
}

bool FileStore::write(int64_t userId, const std::string& storageKey,
                      const char* data, size_t size) const {
    std::error_code ec;
    fs::create_directories(userDir(userId), ec);
    if (ec) {
        utils::Logger::get_instance().error("FileStore::write mkdir: " + ec.message());
        return false;
    }

    std::ofstream out(pathFor(userId, storageKey), std::ios::binary | std::ios::trunc);
    if (!out) return false;
    if (size > 0) out.write(data, static_cast<std::streamsize>(size));
    return out.good();
}

bool FileStore::remove(int64_t userId, const std::string& storageKey) const {
    std::error_code ec;
    fs::remove(pathFor(userId, storageKey), ec);
    return !ec;
}
