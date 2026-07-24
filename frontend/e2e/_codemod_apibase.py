#!/usr/bin/env python3
"""
Codemod: replace hardcoded `const API = "http://localhost:8000";` (and the
127.0.0.1 variant) in e2e specs with an import from ./cpp.config, so the API
base can be overridden via E2E_API_BASE (cpp backend).

- Only rewrites files whose API const is EXACTLY the localhost/127.0.0.1:8000
  string literal. Files using `const API = BASE` (BASE = http://localhost:3000,
  a frontend base) or route-path literals are left untouched and reported.
- Import path is computed relative to each spec so subdir specs still resolve.
"""
import os, re

E2E_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_MODULE = os.path.join(E2E_DIR, "cpp.config.ts")

CONST_RE = re.compile(
    r"""^[ \t]*const[ \t]+API[ \t]*=[ \t]*["'](?:http://localhost:8000|http://127\.0\.0\.1:8000)["'];[ \t]*\r?\n""",
    re.MULTILINE,
)
IMPORT_RE = re.compile(r"""^import[ \t].*?;[ \t]*\r?\n""", re.MULTILINE)


def rel_import(spec_path):
    rel = os.path.relpath(os.path.splitext(CONFIG_MODULE)[0], os.path.dirname(spec_path))
    rel = rel.replace(os.sep, "/")
    if not rel.startswith("."):
        rel = "./" + rel
    return rel


def process(spec_path):
    with open(spec_path, "r", encoding="utf-8") as fh:
        src = fh.read()
    if not CONST_RE.search(src):
        return None
    new_src, n = CONST_RE.subn("", src)
    if n == 0:
        return None
    import_line = 'import { API } from "%s";\n' % rel_import(spec_path)
    imp_iter = list(IMPORT_RE.finditer(new_src))
    if imp_iter:
        pos = imp_iter[-1].end()
        new_src = new_src[:pos] + import_line + new_src[pos:]
    else:
        new_src = import_line + new_src
    with open(spec_path, "w", encoding="utf-8") as fh:
        fh.write(new_src)
    return n


def main():
    changed = []
    skipped_base = []
    total = 0
    for name in sorted(os.listdir(E2E_DIR)):
        if not name.endswith(".spec.ts"):
            continue
        p = os.path.join(E2E_DIR, name)
        with open(p, "r", encoding="utf-8") as fh:
            s = fh.read()
        if "const API = BASE" in s and not CONST_RE.search(s):
            skipped_base.append(name)
        n = process(p)
        if n:
            changed.append(name)
            total += n
    print("changed files: %d" % len(changed))
    print("const declarations removed: %d" % total)
    print("skipped (const API = BASE, frontend :3000 base): %d" % len(skipped_base))
    for f in skipped_base:
        print("  SKIP %s" % f)


if __name__ == "__main__":
    main()
