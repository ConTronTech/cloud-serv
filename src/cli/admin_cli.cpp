#include "cli/admin_cli.h"

#include "core/config.h"
#include "db/database.h"
#include "security/crypto.h"
#include "security/e2e_keys.h"
#include "utils/logger.h"
#include "storage/tree_store.h"
#include "storage/tree_scan.h"

#include <openssl/crypto.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <regex>
#include <string>

namespace cli {

namespace {

void usage(std::FILE* to) {
    std::fputs(
        "cloud-serv local administration (works directly on the database, never over HTTP)\n"
        "\n"
        "usage:\n"
        "  cloud_serv admin create-admin --email <email> [options]\n"
        "  cloud_serv admin set-tree --email <email> --dir <name> [--config <file>]\n"
        "  cloud_serv admin rescan   --email <email> [--config <file>]\n"
        "\n"
        "create-admin creates a fully working ADMIN account, including its end-to-end\n"
        "encryption keys, so you can then sign in from the web UI with that email and\n"
        "password. No invite code and no open registration needed.\n"
        "\n"
        "options:\n"
        "  --email <email>              the account's email (required)\n"
        "  --name <display name>        defaults to the part of the email before the @\n"
        "  --config <file>              config file (default: config.env)\n"
        "  --password-stdin             read the password from one line of stdin instead\n"
        "                               of prompting (for scripts). Never pass a password\n"
        "                               as an argument: it would be visible in `ps`.\n"
        "  --recovery-key-file <path>   write the recovery key to this NEW file (mode 0600)\n"
        "                               instead of printing it. Refuses to overwrite.\n"
        "\n"
        "The recovery key is the ONLY way back into the account's data if the password is\n"
        "forgotten. It is shown once and cannot be recovered afterwards.\n"
        "\n"
        "set-tree switches an account to real-folder storage: its files live as a normal\n"
        "folder tree at <TREE_ROOT>/<name>/ (docs/REAL_FOLDERS.md). The account must have\n"
        "no files yet and encryption is turned off for it. Files already in that folder are\n"
        "indexed straight away.\n"
        "\n"
        "rescan indexes a real-folder account's tree now and prints what changed. Prefer\n"
        "`kill -HUP <server pid>` (cloudctl rescan) while the server runs; this command is\n"
        "for a stopped server, e.g. right after moving a big tree in.\n",
        to);
}

std::string lowered(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Same rule the server applies to registrations.
bool validEmail(const std::string& e) {
    static const std::regex re(R"(^[^@\s]+@[^@\s]+\.[^@\s]+$)");
    return e.size() <= 254 && std::regex_match(e, re);
}

// Echo off while typing a password; restored on every exit path.
struct EchoOff {
    termios saved{};
    bool active = false;
    EchoOff() {
        if (tcgetattr(STDIN_FILENO, &saved) == 0) {
            termios t = saved;
            t.c_lflag &= ~static_cast<tcflag_t>(ECHO);
            active = tcsetattr(STDIN_FILENO, TCSAFLUSH, &t) == 0;
        }
    }
    ~EchoOff() { if (active) tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved); }
};

bool promptHidden(const char* label, std::string& out) {
    std::fputs(label, stderr);
    std::fflush(stderr);
    {
        EchoOff off;
        if (!std::getline(std::cin, out)) { std::fputc('\n', stderr); return false; }
    }
    std::fputc('\n', stderr);
    if (!out.empty() && out.back() == '\r') out.pop_back();
    return true;
}

void wipe(std::string& s) {
    if (!s.empty()) OPENSSL_cleanse(&s[0], s.size());
    s.clear();
}

// Write `text` to a NEW file with mode 0600. false if the path already exists
// (or anything else goes wrong): the caller must never lose a key silently.
bool writeNewSecretFile(const std::string& path, const std::string& text) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < text.size()) {
        ssize_t n = ::write(fd, text.data() + off, text.size() - off);
        if (n <= 0) { ::close(fd); ::unlink(path.c_str()); return false; }
        off += static_cast<size_t>(n);
    }
    bool ok = ::fsync(fd) == 0;
    ::close(fd);
    if (!ok) ::unlink(path.c_str());
    return ok;
}

int fail(const std::string& msg) {
    std::fprintf(stderr, "error: %s\n", msg.c_str());
    return 1;
}

int createAdmin(int argc, char** argv) {
    std::string email, name, configPath = "config.env", recoveryFile;
    bool passwordStdin = false;
    for (int i = 0; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](std::string& dst) -> bool {
            if (i + 1 >= argc) return false;
            dst = argv[++i];
            return true;
        };
        if (a == "--email") { if (!next(email)) { usage(stderr); return 2; } }
        else if (a == "--name") { if (!next(name)) { usage(stderr); return 2; } }
        else if (a == "--config") { if (!next(configPath)) { usage(stderr); return 2; } }
        else if (a == "--recovery-key-file") { if (!next(recoveryFile)) { usage(stderr); return 2; } }
        else if (a == "--password-stdin") passwordStdin = true;
        else {
            std::fprintf(stderr, "error: unknown option '%s'%s\n", a.c_str(),
                         a == "--password" ? " (a password must never be passed as an argument; it would show in `ps`. Use the prompt or --password-stdin)" : "");
            usage(stderr);
            return 2;
        }
    }
    if (email.empty()) { std::fputs("error: --email is required\n", stderr); usage(stderr); return 2; }
    email = lowered(email);
    if (!validEmail(email)) return fail("that is not a valid email address");
    if (name.empty()) name = email.substr(0, email.find('@'));
    if (name.size() > 100) return fail("display name is too long (max 100)");

    // ---- password (never from argv) ----
    std::string password;
    if (passwordStdin) {
        if (!std::getline(std::cin, password)) return fail("no password on stdin");
        if (!password.empty() && password.back() == '\r') password.pop_back();
    } else {
        if (!isatty(STDIN_FILENO))
            return fail("stdin is not a terminal; use --password-stdin to supply the password from a script");
        std::string confirm;
        if (!promptHidden("Password: ", password) || !promptHidden("Confirm password: ", confirm)) {
            wipe(password); wipe(confirm);
            return fail("no password entered");
        }
        bool same = password == confirm;
        wipe(confirm);
        if (!same) { wipe(password); return fail("the passwords do not match"); }
    }
    if (password.size() < 8) { wipe(password); return fail("password must be at least 8 characters"); }

    // ---- open the database the server uses ----
    utils::Logger::get_instance().init(utils::LogLevel::ERROR);   // before anything logs: keep the tool's output clean
    try {
        core::Config::get_instance().load(configPath);
    } catch (const std::exception& e) {
        wipe(password);
        return fail("cannot read config '" + configPath + "': " + e.what());
    }
    const std::string dbPath = core::Config::get_instance().get("env", "DB_PATH", "data/cloud.db");
    {
        std::error_code ec;
        std::filesystem::path p(dbPath);
        if (p.has_parent_path()) {
            std::filesystem::create_directories(p.parent_path(), ec);
            ::chmod(p.parent_path().c_str(), S_IRWXU);
        }
    }

    int rc = 1;
    try {
        CloudDB db(dbPath);
        if (db.findUserByEmail(email)) { wipe(password); return fail("an account with that email already exists"); }

        // The heavy part: real key derivation (PBKDF2 x 310000), same as the browser.
        security::e2e::AccountKeys keys = security::e2e::generateAccountKeys(password);
        wipe(password);

        // The recovery key goes to a file FIRST, before the account exists, so a
        // failure to save it can never leave an account whose key is lost.
        if (!recoveryFile.empty()) {
            if (!writeNewSecretFile(recoveryFile, keys.recoveryKey + "\n"))
                return fail("could not create the recovery key file '" + recoveryFile +
                            "' (it must not already exist); no account was created");
        }
        auto undoKeyFile = [&]() { if (!recoveryFile.empty()) ::unlink(recoveryFile.c_str()); };

        int64_t id = db.createUser(email, name, security::Crypto::hashPassword(keys.authKeyB64));
        if (id < 0) { undoKeyFile(); return fail("could not create the account"); }
        if (!db.setUserKeys(id, keys.saltHex, keys.wrappedDek, keys.wrappedDekRecovery) ||
            !db.setUserRole(id, "admin")) {
            db.wipeUser(id, /*byAdminId=*/0, "");   // don't leave a half-made account behind
            undoKeyFile();
            return fail("could not finish creating the account; nothing was kept");
        }

        std::printf("Created admin account '%s' (id %lld).\n", email.c_str(), static_cast<long long>(id));
        std::printf("Sign in from the web UI with this email and the password you just set.\n");
        if (!recoveryFile.empty()) {
            std::printf("\nRecovery key written to %s (mode 0600). Store it somewhere safe and\n"
                        "offline, then delete this file. It is the ONLY way back into the account's\n"
                        "data if the password is forgotten.\n", recoveryFile.c_str());
        } else {
            std::printf("\n================ RECOVERY KEY (shown once) ================\n"
                        "%s\n"
                        "===========================================================\n"
                        "This is the ONLY way back into the account's data if the password is\n"
                        "forgotten. Write it down somewhere safe and offline; it cannot be shown again.\n",
                        keys.recoveryKey.c_str());
        }
        rc = 0;
    } catch (const std::exception& e) {
        wipe(password);
        return fail(e.what());
    }
    return rc;
}

} // namespace

// Shared by set-tree / rescan: parse --email/--dir/--config, load config, open the DB.
struct TreeArgs { std::string email, dir, configPath = "config.env"; };
int parseTreeArgs(int argc, char** argv, TreeArgs& a, bool needDir) {
    for (int i = 0; i < argc; ++i) {
        const std::string o = argv[i];
        auto next = [&](std::string& dst) { if (i + 1 >= argc) return false; dst = argv[++i]; return true; };
        if (o == "--email") { if (!next(a.email)) return 2; }
        else if (o == "--dir" && needDir) { if (!next(a.dir)) return 2; }
        else if (o == "--config") { if (!next(a.configPath)) return 2; }
        else { std::fprintf(stderr, "error: unknown option '%s'\n", o.c_str()); return 2; }
    }
    if (a.email.empty() || (needDir && a.dir.empty())) { usage(stderr); return 2; }
    a.email = lowered(a.email);
    utils::Logger::get_instance().init(utils::LogLevel::ERROR);
    try { core::Config::get_instance().load(a.configPath); }
    catch (const std::exception& e) { return fail("cannot read config '" + a.configPath + "': " + e.what()); }
    return 0;
}

int printScan(const storage::TreeScanResult& r) {
    if (!r.ok) return fail("scan failed (see the server log / is the account folder readable?)");
    const auto& s = r.stats;
    std::printf("scan done in %.1f s: +%lld folders, +%lld files, %lld updated, -%lld folders, -%lld files; trash purged %d\n",
                r.seconds, (long long)s.foldersAdded, (long long)s.filesAdded, (long long)s.filesUpdated,
                (long long)s.foldersRemoved, (long long)s.filesRemoved, r.trashPurged);
    if (!r.skipped.empty()) {
        std::printf("%zu entries were NOT indexed (they stay on disk untouched):\n", r.skipped.size());
        size_t shown = 0;
        for (const auto& k : r.skipped) { if (shown++ == 50) { std::printf("  ...\n"); break; } std::printf("  %s\n", k.c_str()); }
    }
    return 0;
}

int setTree(int argc, char** argv) {
    TreeArgs a;
    if (int rc = parseTreeArgs(argc, argv, a, true)) return rc;
    auto& cfg = core::Config::get_instance();
    TreeStore tree(cfg.get("env", "TREE_ROOT", ""), cfg.get_int("env", "TRASH_DAYS", 30));
    if (!tree.enabled()) return fail("TREE_ROOT is not set in the config");
    if (!TreeStore::validAccountDir(a.dir)) return fail("--dir must be letters, digits, - _ . (not starting with '.')");
    try {
        CloudDB db(cfg.get("env", "DB_PATH", "data/cloud.db"));
        auto u = db.findUserByEmail(a.email);
        if (!u) return fail("no account with that email");
        if (auto cur = db.treeDir(u->id)) {
            if (*cur == a.dir) { std::printf("'%s' already uses real folders at %s/%s\n", a.email.c_str(), tree.root().c_str(), cur->c_str()); return 0; }
            return fail("account already uses real folders at '" + *cur + "'");
        }
        for (const auto& [uid, dir] : db.treeAccounts())
            if (dir == a.dir) return fail("another account already uses '" + a.dir + "'");
        if (db.usage(u->id).second > 0)
            return fail("the account already has files in normal storage; real folders are for empty accounts");
        if (!tree.ensureAccount(a.dir)) return fail("cannot create or open " + tree.root() + "/" + a.dir);
        if (!db.setTreeMode(u->id, a.dir)) return fail("could not update the account");
        std::printf("'%s' now uses real folders at %s/%s (encryption off).\n", a.email.c_str(), tree.root().c_str(), a.dir.c_str());
        return printScan(storage::scanTreeAccount(db, tree, u->id, a.dir));
    } catch (const std::exception& e) { return fail(e.what()); }
}

int rescan(int argc, char** argv) {
    TreeArgs a;
    if (int rc = parseTreeArgs(argc, argv, a, false)) return rc;
    auto& cfg = core::Config::get_instance();
    TreeStore tree(cfg.get("env", "TREE_ROOT", ""), cfg.get_int("env", "TRASH_DAYS", 30));
    if (!tree.enabled()) return fail("TREE_ROOT is not set in the config");
    try {
        CloudDB db(cfg.get("env", "DB_PATH", "data/cloud.db"));
        auto u = db.findUserByEmail(a.email);
        if (!u) return fail("no account with that email");
        auto dir = db.treeDir(u->id);
        if (!dir) return fail("that account does not use real folders");
        return printScan(storage::scanTreeAccount(db, tree, u->id, *dir));
    } catch (const std::exception& e) { return fail(e.what()); }
}

int runAdminCli(int argc, char** argv) {
    // argv[0] == "admin"
    if (argc < 2 || std::string(argv[1]) == "help" || std::string(argv[1]) == "--help" ||
        std::string(argv[1]) == "-h") {
        usage(argc < 2 ? stderr : stdout);
        return argc < 2 ? 2 : 0;
    }
    const std::string cmd = argv[1];
    if (cmd == "create-admin") return createAdmin(argc - 2, argv + 2);
    if (cmd == "set-tree") return setTree(argc - 2, argv + 2);
    if (cmd == "rescan") return rescan(argc - 2, argv + 2);
    std::fprintf(stderr, "error: unknown admin command '%s'\n", cmd.c_str());
    usage(stderr);
    return 2;
}

} // namespace cli
