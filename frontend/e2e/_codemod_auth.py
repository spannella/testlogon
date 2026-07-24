#!/usr/bin/env python3
"""
W2.5 codemod: repoint the per-spec Python-seeded getSessions()/getAdminSessions()
caches at the cpp-aware loadSessions() helper (e2e/helpers/session.ts).

Why: ~half the specs authenticate cpp with Python-minted JWT cookies from
e2e_session_setup.py / e2e_admin_session_setup.py. cpp rejects those (different
secret + revocable-session model + sub-not-email resolution) -> 401 -> UI-timeout
cascade. loadSessions() already does REAL cpp logins (or F2 storageState fallback)
when E2E_USE_CPP=1 / non-Python E2E_API_BASE, and returns the SAME key set the
Python seeders emit (short names root/alice/bob/charlie_admin/... PLUS the
e2e_*@test.local email aliases). Under the default Python path loadSessions()
still shells to e2e_admin_session_setup.py, so behavior is unchanged.

Transform (idempotent, per file):
  const <raw> = execSync(<...e2e_(admin_)?session_setup.py...>)....toString();
  [const lastLine = <raw>....;]
  <CACHE> = JSON.parse(<raw|lastLine>);
    ->
  <CACHE> = loadSessions();
and inject:  import { loadSessions } from "./helpers/session";

Files whose auth is too bespoke to match are left untouched and reported.
"""
import re
import sys
import glob
import os

E2E_DIR = os.path.dirname(os.path.abspath(__file__))

# execSync(...) whose argument mentions one of the two Python session seeders,
# ending in .toString(); assigned to a raw var. Non-greedy across newlines.
#   const <raw> = execSync(<...seeder...>).toString();   (seeder named inline OR
#     via a `${setupScript}` template where setupScript = ...session_setup.py)
#   [const lastLine = <raw>.trim()...;  |  jsonStart lookups etc.]
#   <CACHE> = JSON.parse(<pv-expr>) [as <Type>];
# pv-expr may be a bare var or a chained expression (raw.trim()..., raw.slice(n)).
SEED_RE = re.compile(
    r"""const\s+(?P<raw>\w+)\s*=\s*execSync\(
        (?P<args>(?:[^;]*?(?:e2e_(?:admin_)?session_setup\.py|\$\{setupScript\})[^;]*?))
        \)(?:\s*\.toString\(\))?\s*;                       # optional .toString()
        (?P<mid>(?:\s*(?://[^\n]*\n|const\s+\w+\s*=[^;]*;))*)  # comments / intermediates
        \s*(?P<cache>\w+)\s*=\s*JSON\.parse\(\s*[^;]*?\)  # JSON.parse(<expr>)
        (?:\s*as\s+[^;]+?)?\s*;                            # optional `as <Type>` cast
    """,
    re.VERBOSE | re.DOTALL,
)

# Module-level inline form (not wrapped in a getSessions() fn):
#   const <name>[: <Type>] = JSON.parse( execSync(<...seeder...>)[.toString()] )
#                            [ as <Type> ];
# -> const <name>[: <Type>] = loadSessions()[ as <Type> ];
MODULE_RE = re.compile(
    r"""(?P<decl>const\s+\w+(?:\s*:\s*[^=]+?)?\s*=\s*)
        JSON\.parse\(\s*
        \w+\(\s*                                  # execSync( / execFileSync(
        [^;]*?(?:e2e_(?:admin_)?session_setup\.py)[^;]*?
        \)\s*(?:\.toString\(\))?\s*,?\s*
        \)\s*
        (?P<cast>as\s+[^;]+?)?\s*;
    """,
    re.VERBOSE | re.DOTALL,
)

IMPORT_LINE = 'import { loadSessions } from "./helpers/session";'


def transform(text):
    n = 0

    def repl(m):
        nonlocal n
        n += 1
        return "%s = loadSessions();" % m.group("cache")

    new = SEED_RE.sub(repl, text)

    def mod_repl(m):
        nonlocal n
        n += 1
        cast = m.group("cast")
        return "%sloadSessions()%s;" % (
            m.group("decl"),
            (" " + cast) if cast else "",
        )

    new = MODULE_RE.sub(mod_repl, new)

    if n == 0:
        return text, 0
    if IMPORT_LINE not in new:
        lines = new.split("\n")
        # Anchor to TS ES-module imports only (`import ... from "..."`). Bare
        # `import boto3` lines exist inside Python heredoc template literals and
        # must NOT be treated as insertion points.
        ts_imp = re.compile(r'^\s*import\b.*\bfrom\s+["\']')
        last_imp = max(
            (i for i, l in enumerate(lines) if ts_imp.match(l)),
            default=-1,
        )
        if last_imp >= 0:
            lines.insert(last_imp + 1, IMPORT_LINE)
        else:
            lines.insert(0, IMPORT_LINE)
        new = "\n".join(lines)
    return new, n


def main():
    apply = "--apply" in sys.argv
    files = sorted(glob.glob(os.path.join(E2E_DIR, "*.spec.ts")))
    changed, skipped_bespoke, subs_total = [], [], 0
    for f in files:
        with open(f, "r", encoding="utf-8") as fh:
            text = fh.read()
        if "session_setup.py" not in text:
            continue
        new, n = transform(text)
        if n == 0:
            if re.search(r"getSessions\(|getAdminSessions\(", text):
                skipped_bespoke.append(os.path.basename(f))
            continue
        subs_total += n
        changed.append((os.path.basename(f), n))
        if apply and new != text:
            with open(f, "w", encoding="utf-8") as fh:
                fh.write(new)
    print("MODE: %s" % ("APPLY" if apply else "DRY-RUN"))
    print("CHANGED_FILES: %d  TOTAL_SUBS: %d" % (len(changed), subs_total))
    for name, n in changed:
        print("  ~ %s (%d)" % (name, n))
    print("BESPOKE_SKIPPED (seeder ref, no auto-match): %d" % len(skipped_bespoke))
    for name in skipped_bespoke:
        print("  ! %s" % name)


if __name__ == "__main__":
    main()
