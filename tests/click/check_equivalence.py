#!/usr/bin/env python3
"""Check the output of phase2_equivalence.click.

Usage: check_equivalence.py <click output file>
Exit status 0 if every check passes. Prints one line per check.
"""
import sys


def sections(text):
    out, cur = {}, None
    for line in text.splitlines():
        if line.startswith("=== "):
            cur = line[4:].strip()
            out[cur] = []
        elif cur is not None and line.strip():
            out[cur].append(line)
    return out


def parse_look(lines):
    """upstream 'look' format: first line jiffies, then 'ip<TAB>fwd<TAB>rev' with
    nested levels prefixed by tabs and the parent's dotted prefix."""
    table = {}
    for line in lines[1:]:
        parts = line.strip("\t").split("\t")
        if len(parts) < 3:
            continue
        table[parts[-3]] = (float(parts[-2]), float(parts[-1]))
    return table


def main():
    text = open(sys.argv[1]).read()
    s = sections(text)
    failures = 0

    def check(name, ok, detail=""):
        nonlocal failures
        print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")
        failures += 0 if ok else 1

    up, coop = parse_look(s["up.look"]), parse_look(s["coop.look"])
    e_up, e_coop = int(s["up.look"][0]), int(s["coop.look"][0])
    check("look header (epochs since reset) matches", abs(e_up - e_coop) <= 1, f"({e_up} vs {e_coop})")
    check("same set of active prefixes", set(up) == set(coop),
          f"(up {len(up)}, coop {len(coop)}; only-up {sorted(set(up) - set(coop))}, "
          f"only-coop {sorted(set(coop) - set(up))})")
    worst = 0.0
    for k in sorted(set(up) & set(coop)):
        for i in range(2):
            a, b = up[k][i], coop[k][i]
            err = abs(a - b) / max(1.0, abs(a))
            worst = max(worst, err)
    check("rates agree within 2% (relative)", worst <= 0.02, f"(worst relative difference {worst:.4%})")

    for name, prefix, depth in (("A host", "10.0.0.1", 4), ("C host", "172.16.0.9", 4)):
        check(f"{name} expanded to /32 in both", prefix in up and prefix in coop)
    check("B stays at /8 (50 pps < THRESH 100)", "192" in coop and "192.168" not in coop)

    exports = int(s["coop.exports"][0])
    check("export timer fired ~once per second", 4 <= exports <= 6, f"(exports={exports})")
    stats = dict(l.split() for l in s["coop.stats"])
    check("coop invariants ok", stats.get("invariants") == "ok")

    snap = {}
    for line in s["tot.snapshot"]:
        if line.startswith("#") or line.startswith("prefix"):
            continue
        f = line.split(",")
        snap[f[0]] = (int(f[4]), int(f[5]))
    cA, cB, cC = (int(x) for x in s["counts"][:3])
    check("exact fwd count 10.0.0.0/8 == Counter A", snap.get("10.0.0.0/8", (None,))[0] == cA,
          f"({snap.get('10.0.0.0/8')} vs {cA})")
    check("exact fwd count 192.0.0.0/8 == Counter B", snap.get("192.0.0.0/8", (None,))[0] == cB,
          f"({snap.get('192.0.0.0/8')} vs {cB})")
    check("exact rev count 172.0.0.0/8 == Counter C", snap.get("172.0.0.0/8", (None, None))[1] == cC,
          f"({snap.get('172.0.0.0/8')} vs {cC})")
    print(f"\n{failures} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
