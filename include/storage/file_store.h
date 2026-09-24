#pragma once

#include <string>
#include <cstdint>
#include <vector>

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

    // Account lifecycle (admin remove/wipe):
    // Populate destDir (created 0700) with every regular file in the user's
    // directory. Hard-links when possible (instant, no extra disk) and falls
    // back to a real copy when linking isn't possible (e.g. different
    // filesystems). A user with no directory yields an empty destDir and
    // success. The blobs are still ciphertext; this never reads them.
    bool stageUserDir(int64_t userId, const std::string& destDir) const;
    // Delete the user's whole directory. Missing directory is success.
    bool removeUserDir(int64_t userId) const;
    // Restore: put each listed blob from srcDir back into the user's live
    // directory (hard link, else copy). All-or-nothing: on any failure the blobs
    // this call placed are removed again and false is returned. A blob already
    // present as the very same file is left alone.
    bool restoreBlobs(int64_t userId, const std::string& srcDir,
                      const std::vector<std::string>& keys) const;
    // Undo for restoreBlobs when a later step fails: delete these blobs.
    void removeBlobs(int64_t userId, const std::vector<std::string>& keys) const;

private:
    std::string baseDir_;
    std::string userDir(int64_t userId) const;
};
