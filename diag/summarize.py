#!/usr/bin/env python3
"""SCRATCH (lot T7-H2MAC): the per-flood verdicts of a --gtest_repeat run of http2-control-replies.

Reads the gtest output: per iteration, each failure's file:line and the SCOPED_TRACE that names the flood; and the
[H2MAC] RESULT lines when the binary is instrumented. Prints the counts per flood, per verdict and per failing line.
"""
import collections
import re
import sys

text = open(sys.argv[1], errors="replace").read().splitlines()
case = "AClientThatNeverReadsIsCutOnceAThousandRepliesAreQueued"
iterations = 0
case_runs = collections.Counter()
failures = collections.Counter()  # (flood, line, message head)
i = 0
while i < len(text):
    line = text[i]
    if line.startswith("Repeating all tests (iteration") or (iterations == 0 and line.startswith("[==========] Running")):
        iterations += 1
    m = re.match(r"\[ +(OK|FAILED) +\] Http2ControlRepliesWireTest\.(\w+) \(", line)
    if m and m.group(2) == case:
        case_runs[m.group(1)] += 1
    m = re.search(r"http2-control-replies\.cpp:(\d+): Failure", line)
    if m:
        where = m.group(1)
        head = text[i + 1].strip() if i + 1 < len(text) else ""
        flood = "?"
        for j in range(i + 1, min(i + 40, len(text))):
            if text[j].startswith("Google Test trace:"):
                t = re.search(r"http2-control-replies\.cpp:\d+: (.*)$", text[j + 1]) if j + 1 < len(text) else None
                if t:
                    flood = t.group(1).strip()
                break
            if re.search(r"\.cpp:\d+: Failure", text[j]) or text[j].startswith("[  FAILED  ]") or text[j].startswith("[       OK ]"):
                break
        failures[(flood, where, head[:90])] += 1
    i += 1

print(f"iterations: {iterations}; the flood case: OK x{case_runs['OK']}, FAILED x{case_runs['FAILED']}")
print("failures (flood, line, first line of the message):")
for (flood, where, head), n in sorted(failures.items(), key=lambda kv: (-kv[1], kv[0])):
    print(f"  {n:3d}  {flood!r} :{where}  {head}")

per = collections.Counter()
shapes = collections.Counter()
for line in text:
    m = re.match(r"\[H2MAC\] RESULT flood=(.*?) verdict=(\w+) (.*)", line)
    if not m:
        continue
    flood, verdict, rest = m.groups()
    per[(flood, verdict)] += 1
    kv = dict(re.findall(r"(\w+)=(\{[^}]*\}|\S+)", rest))
    shapes[(flood, verdict, kv.get("held10"), kv.get("late"), kv.get("write_fail_errno"), kv.get("read_fail_errno"), kv.get("server_ok"))] += 1
if per:
    print("[H2MAC] per flood:")
    for (flood, verdict), n in sorted(per.items()):
        print(f"  flood {flood!r}: {verdict} x{n}")
    print("[H2MAC] shapes (flood, verdict, held10, late, client write errno, client read errno, server_ok):")
    for k, n in sorted(shapes.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {n:3d} {k}")
