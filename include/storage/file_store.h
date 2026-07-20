#pragma once

#include <string>
#include <cstdint>

// FileStore — persists file blobs on disk, one directory per user:
//   <baseDir>/<userId>/<storageKey>
// Metadata (name, mime, size) lives in CloudDB; this only moves bytes.
class FileStore {
public:
    explicit FileStore(const std::string& baseDir);

    // Absolute path where a user's blob lives (does not touch the filesystem).
    std::string pathFor(int64_t userId, const std::string& storageKey) const;

    // Write bytes for a user's blob, creating the user dir if needed. false on error.
    bool write(int64_t userId, const std::string& storageKey,
               const char* data, size_t size) const;

    // Append bytes to an existing blob (used by chunked uploads). Creates the
    // user dir + file if needed. false on error.
    bool append(int64_t userId, const std::string& storageKey,
                const char* data, size_t size) const;

    // Current size of a blob on disk (-1 if it doesn't exist).
    int64_t sizeOf(int64_t userId, const std::string& storageKey) const;

    // Delete a blob. Missing file is treated as success.
    bool remove(int64_t userId, const std::string& storageKey) const;

private:
    std::string baseDir_;
    std::string userDir(int64_t userId) const;
};
