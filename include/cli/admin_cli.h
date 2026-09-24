#pragma once

namespace cli {

// `cloud_serv admin ...` — local administration that works directly on the
// database, never over HTTP. argv[0] is the word "admin" (the caller strips the
// program name). Returns the process exit code (0 ok, 1 failure, 2 usage error).
int runAdminCli(int argc, char** argv);

} // namespace cli
