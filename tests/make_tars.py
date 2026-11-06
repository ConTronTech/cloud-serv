#!/usr/bin/env python3
"""Build tar archives for tests/test_tree_archive.sh.  Usage: make_tars.py <outdir>"""
import io, os, sys, tarfile, time

out = sys.argv[1]
os.makedirs(out, exist_ok=True)


def add_file(t, name, data, mtime=1700000000):
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    ti.mtime = mtime
    t.addfile(ti, io.BytesIO(data))


def add_dir(t, name):
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.DIRTYPE
    ti.mode = 0o755
    t.addfile(ti)


def add_link(t, name, target, kind):
    ti = tarfile.TarInfo(name)
    ti.type = kind
    ti.linkname = target
    t.addfile(ti)


long_dir = "deep/" + "/".join(["level-%02d-with-a-longish-name" % i for i in range(8)])

# good.tar: nested dirs, empty dir, long path (pax), unicode, 0-byte, a 1 MB file
with tarfile.open(f"{out}/good.tar", "w", format=tarfile.PAX_FORMAT) as t:
    add_dir(t, "src")
    add_file(t, "src/main.js", b"console.log('hi')\n")
    add_file(t, "src/lib/util.js", b"export const x = 1;\n")
    add_dir(t, "empty-folder")
    add_file(t, "README.md", b"# project\n")
    add_file(t, "zero.bin", b"")
    add_file(t, f"{long_dir}/far.txt", b"far away\n")
    add_file(t, "unicode-éè-日本.txt", "café\n".encode())
    add_file(t, "big.bin", bytes(range(256)) * 4096)
    add_link(t, "a-symlink", "/etc/passwd", tarfile.SYMTYPE)           # skipped, never created

# gnu.tar: GNU long-name entries instead of pax
with tarfile.open(f"{out}/gnu.tar", "w", format=tarfile.GNU_FORMAT) as t:
    add_file(t, f"{long_dir}/gnu-far.txt", b"gnu\n")
    add_file(t, "plain.txt", b"plain\n")

# hostile archives: each must be rejected whole
with tarfile.open(f"{out}/dotdot.tar", "w") as t:
    add_file(t, "ok.txt", b"fine")
    add_file(t, "../escaped.txt", b"ESCAPE")
with tarfile.open(f"{out}/absolute.tar", "w") as t:
    add_file(t, "/tmp/abs-escape.txt", b"ESCAPE")
with tarfile.open(f"{out}/nested-dotdot.tar", "w") as t:
    add_file(t, "a/b/../../../escaped2.txt", b"ESCAPE")
# hardlink + reserved names: skipped, archive still accepted
with tarfile.open(f"{out}/odd.tar", "w") as t:
    add_file(t, "keep.txt", b"keep")
    add_link(t, "hard", "keep.txt", tarfile.LNKTYPE)
    add_file(t, ".trash/sneaky.txt", b"no")
    add_file(t, "sub/.cloud-serv/sneaky.txt", b"no")
# duplicate entry for the same path: rejected
with tarfile.open(f"{out}/dup.tar", "w") as t:
    add_file(t, "same.txt", b"one")
    add_file(t, "same.txt", b"two")

# truncated: valid start, cut mid-file
data = open(f"{out}/good.tar", "rb").read()
open(f"{out}/truncated.tar", "wb").write(data[: len(data) // 2 + 100])
# garbage: not a tar at all
open(f"{out}/garbage.tar", "wb").write(os.urandom(4096))
print("ok")
