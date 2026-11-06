#pragma once

#include <cstdint>
#include <string>

// TarStream — unpack a tar archive as it arrives, chunk by chunk, into a directory.
//
// Used for folder uploads on real-folder accounts: the browser packs the folder as an
// uncompressed tar and sends it through the normal chunked upload; every chunk is fed
// here, so the files are written once, straight into a staging dir on the same drive.
//
// Understands ustar (name + prefix), GNU long names ('L') and pax headers ('x': path,
// size, mtime). Regular files and directories are created; links, devices and fifos are
// skipped and counted. Anything that tries to leave the root (absolute paths, "..") stops
// the whole archive. Every component is created/opened with O_NOFOLLOW from the root fd.
class TarStream {
public:
    // Takes ownership of rootFd (a directory). Nothing outside it is ever touched.
    explicit TarStream(int rootFd);
    ~TarStream();
    TarStream(const TarStream&) = delete;
    TarStream& operator=(const TarStream&) = delete;

    // Feed the next bytes. false = the archive is rejected; see error().
    bool feed(const char* data, size_t size);
    // The upload is complete: false if the archive stopped mid-entry.
    bool finish();
    const std::string& error() const { return error_; }

    int64_t files = 0, dirs = 0, skipped = 0, bytes = 0;
    static const int64_t kMaxEntries = 4'000'000;

private:
    enum class St { Header, Data, Meta, Pad, End, Failed };
    int root_;
    St st_ = St::Header;
    char hdr_[512];
    size_t hdrLen_ = 0;
    int zeroBlocks_ = 0;
    int64_t remaining_ = 0;   // data bytes left in the current entry
    int64_t pad_ = 0;         // padding bytes to skip after the data
    int out_ = -1;            // open file being written (-1 = discarding data)
    int64_t outMtime_ = 0;
    char metaType_ = 0;       // 'L' or 'x' while collecting a meta entry
    std::string meta_;
    std::string nextPath_;    // from 'L' / pax path=
    int64_t nextSize_ = -1;   // from pax size=
    int64_t nextMtime_ = -1;  // from pax mtime=
    int64_t entries_ = 0;
    std::string error_;

    bool fail(const std::string& msg);
    bool onHeader();
    bool beginEntry(char type, const std::string& path, int64_t size, int64_t mtime);
    void endData();
    void parsePax(const std::string& recs);
    // Split + validate a path. 1 = ok, 0 = skip this entry (bad name), -1 = reject archive.
    int splitPath(const std::string& path, std::string& parentOut, std::string& nameOut, int& depth);
    int openParent(const std::string& rel, bool create);   // fd or -1
};
