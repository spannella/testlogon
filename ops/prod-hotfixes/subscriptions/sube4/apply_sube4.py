#!/usr/bin/env python3
"""SUB-E4 anchored idempotent patch: append the creator subscriber-list +
MRR/analytics endpoints to app/routers/subscription_server.py.

Idempotent: skips if the SUB-E4 sentinel already present. Anchored on the
`run_renewal_sweep(now=now_override, limit=limit)` return line (unique on both
the dev clone and prod), so it applies cleanly on either tree. Appends the block
at END OF FILE (all referenced helpers/models are defined in the block).

Usage: ROOT=/path/to/repo python3 apply_sube4.py   (default ROOT=cwd)
Reads the block from sube4_block.py sitting next to this script.
"""
import os
import sys

ROOT = os.environ.get("ROOT") or os.getcwd()
TARGET = os.path.join(ROOT, "app", "routers", "subscription_server.py")
HERE = os.path.dirname(os.path.abspath(__file__))
BLOCK_FILE = os.path.join(HERE, "sube4_block.py")

SENTINEL = "SUB-E4 — CREATOR SUBSCRIBER MANAGEMENT"
ANCHOR = "return run_renewal_sweep(now=now_override, limit=limit)"

with open(TARGET, "r", encoding="utf-8") as f:
    src = f.read()

if SENTINEL in src:
    print("SKIP: SUB-E4 block already present in", TARGET)
    sys.exit(0)

if ANCHOR not in src:
    print("ERROR: anchor not found in", TARGET)
    sys.exit(2)

with open(BLOCK_FILE, "r", encoding="utf-8") as f:
    block = f.read()

# Append at EOF (block is self-contained). Ensure trailing newline.
if not src.endswith("\n"):
    src += "\n"
src = src + block
if not src.endswith("\n"):
    src += "\n"

with open(TARGET, "w", encoding="utf-8") as f:
    f.write(src)

print("APPLIED: SUB-E4 block appended to", TARGET)

# sanity compile
import py_compile
py_compile.compile(TARGET, doraise=True)
print("PY_COMPILE_OK")
