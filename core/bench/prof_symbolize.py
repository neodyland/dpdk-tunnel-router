#!/usr/bin/env python3
"""Turn engine_prof sample dumps into a per-function profile.

Reads the output of core/bench/engine_prof on stdin:

    # samples: N
    # module <i> <path>
    <module> <offset> <count>

and resolves each (module, offset) with addr2line (falling back to the
nearest exported symbol from nm for modules without debug info).

    make -C core prof-run | core/bench/prof_symbolize.py
    make -C core prof-run | core/bench/prof_symbolize.py --top 25 --exclude make_packet
"""
import argparse
import bisect
import collections
import subprocess
import sys


def addr2line(path, offsets):
    """offset -> 'function at file:line' (or None when unresolvable)."""
    if not offsets:
        return {}
    out = {}
    args = ["addr2line", "-e", path, "-f", "-C", "-p"]
    args += ["0x%x" % off for off in offsets]
    try:
        res = subprocess.run(args, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return {}
    lines = res.stdout.splitlines()
    for off, line in zip(offsets, lines):
        line = line.strip()
        if not line or line.startswith("??"):
            continue
        out[off] = line
    return out


def nm_symbols(path):
    """Sorted (offset, name) list for a module, for nearest-symbol fallback."""
    syms = []
    for flags in (["-D", "--defined-only"], ["--defined-only"]):
        try:
            res = subprocess.run(["nm", "-C", "-n"] + flags + [path],
                                 capture_output=True, text=True, check=False)
        except FileNotFoundError:
            return [], []
        if res.returncode != 0:
            continue
        for line in res.stdout.splitlines():
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            syms.append((addr, parts[2]))
        if syms:
            break
    syms.sort()
    return [s[0] for s in syms], [s[1] for s in syms]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=30)
    ap.add_argument("--exclude", default="",
                    help="comma separated substrings to leave out of the table")
    ap.add_argument("--tags", default="",
                    help="comma separated 'substring=tag' pairs")
    args = ap.parse_args()
    excludes = [s for s in args.exclude.split(",") if s]
    tags = []
    for pair in args.tags.split(","):
        if "=" in pair:
            needle, tag = pair.split("=", 1)
            tags.append((needle, tag))

    modules = {}
    samples = collections.Counter()
    total = 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        if line.startswith("# samples:"):
            total = int(line.split(":", 1)[1])
            continue
        if line.startswith("# module "):
            parts = line.split(None, 3)
            modules[int(parts[2])] = parts[3]
            continue
        if line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3:
            continue
        samples[(int(parts[0]), int(parts[1], 16))] += int(parts[2])

    per_func = collections.Counter()
    per_func_counts = collections.Counter()
    unresolved = 0
    for mod, path in sorted(modules.items()):
        offs = sorted(off for (m, off) in samples if m == mod)
        if not offs:
            continue
        resolved = addr2line(path, offs)
        addrs, names = nm_symbols(path)
        for off in offs:
            n = samples[(mod, off)]
            name = resolved.get(off)
            if name is None:
                unresolved += n
                if addrs:
                    i = bisect.bisect_right(addrs, off) - 1
                    if i >= 0:
                        name = "%s (nearest, %s)" % (names[i], path.split("/")[-1])
                if name is None:
                    name = "?? %s+0x%x" % (path.split("/")[-1], off)
            per_func[name] += n
            per_func_counts[path] += n

    shown = per_func.most_common()
    if excludes:
        kept = [(k, v) for k, v in shown
                if not any(x in k for x in excludes)]
        dropped = sum(v for k, v in shown) - sum(v for _, v in kept)
        shown = kept
    else:
        dropped = 0

    print("samples %d (unresolved %d)" % (total, unresolved))
    print()
    print("%9s %6s  %s" % ("samples", "share", "function"))
    for name, n in shown[: args.top]:
        print("%9d %5.2f%%  %s" % (n, 100.0 * n / max(total, 1), name))

    if tags:
        print()
        print("by group:")
        groups = collections.Counter()
        for name, n in per_func.items():
            label = "other"
            for needle, tag in tags:
                if needle in name:
                    label = tag
                    break
            groups[label] += n
        for label, n in groups.most_common():
            print("  %-28s %9d %5.2f%%" % (label, n, 100.0 * n / max(total, 1)))


if __name__ == "__main__":
    main()
