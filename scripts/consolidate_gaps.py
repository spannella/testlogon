#!/usr/bin/env python3
"""Consolidate per-ticket gap files into GAPS.md + individual GAP-NNNN tickets.

Reads docs/tickets/gaps/<TICKET>.md (each line: "- [SEV] title — `file:line` — impact — Fix: ... — Effort: E"),
emits:
  - docs/tickets/GAPS.md          (master prioritized remediation plan)
  - docs/tickets/gap-tickets/GAP-NNNN-<slug>.md  (one per CRIT/HIGH actionable gap)
Pure stdlib; no AWS / network.
"""
import os, re, glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GAPS_DIR = os.path.join(ROOT, "docs/tickets/gaps")
OUT_TICKETS = os.path.join(ROOT, "docs/tickets/gap-tickets")
os.makedirs(OUT_TICKETS, exist_ok=True)

SEV_ORDER = {"CRIT": 0, "HIGH": 1, "MED": 2, "LOW": 3}
line_re = re.compile(r"^\s*-\s*\[(CRIT|HIGH|MED|LOW|UNBUILT)\]\s*(.*)$")
fileref_re = re.compile(r"`([^`]+)`")

gaps = []   # dicts: ticket, sev, title, fileref, impact, fix, effort, raw
unbuilt = []

for path in sorted(glob.glob(os.path.join(GAPS_DIR, "*.md"))):
    base = os.path.basename(path)
    if base.startswith("_"):
        continue
    ticket = base[:-3]
    with open(path) as f:
        for ln in f:
            m = line_re.match(ln.rstrip())
            if not m:
                continue
            sev, rest = m.group(1), m.group(2).strip()
            if sev == "UNBUILT":
                unbuilt.append(ticket)
                continue
            parts = [p.strip() for p in rest.split(" — ")]
            title = parts[0] if parts else rest
            fileref = ""
            fm = fileref_re.search(rest)
            if fm:
                fileref = fm.group(1)
            impact = ""
            fix = ""
            effort = ""
            for p in parts[1:]:
                if p.startswith("Fix:"):
                    fix = p[4:].strip()
                elif p.startswith("Effort:"):
                    effort = p[7:].strip()
                elif p.startswith("`") and not impact:
                    pass
                elif not p.startswith("`") and "Fix:" not in p and "Effort:" not in p and not impact:
                    impact = p
            gaps.append(dict(ticket=ticket, sev=sev, title=title, fileref=fileref,
                             impact=impact, fix=fix, effort=effort, raw=rest))

unbuilt = sorted(set(unbuilt))
gaps.sort(key=lambda g: (SEV_ORDER[g["sev"]], g["ticket"]))

# tallies
tally = {}
for g in gaps:
    tally[g["sev"]] = tally.get(g["sev"], 0) + 1

# ---- emit GAP-NNNN tickets for CRIT + HIGH ----
def slug(s):
    s = re.sub(r"[`*]", "", s).lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s[:50] or "gap"

actionable = [g for g in gaps if g["sev"] in ("CRIT", "HIGH")]
idx = {}
n = 0
for g in actionable:
    n += 1
    gid = f"GAP-{n:04d}"
    g["gid"] = gid
    fn = os.path.join(OUT_TICKETS, f"{gid}-{slug(g['title'])}.md")
    pr = "Critical" if g["sev"] == "CRIT" else "High"
    body = f"""# {gid}: {g['title']}

**Status**: Open · **Severity**: {g['sev']} ({pr}) · **Source ticket**: {g['ticket']} · **Effort**: {g['effort'] or '?'}
**From**: gap audit (`docs/tickets/gaps/{g['ticket']}.md`); see also `docs/tickets/writeups/{g['ticket']}.md`

## Location
`{g['fileref'] or 'see source ticket'}`

## Problem / Impact
{g['impact'] or g['title']}

## Fix
{g['fix'] or 'See source write-up.'}

## Notes
This gap was identified by the second-pass as-built review of {g['ticket']}. Apply the dev/prod
parity rules in SECOPS-007 if the fix touches AWS-backed paths. Add a regression test
(pytest offline / Playwright) that fails before the fix and passes after.
"""
    with open(fn, "w") as f:
        f.write(body)

# ---- emit GAPS.md master plan ----
by_prefix = {}
for g in gaps:
    pre = re.sub(r"-[0-9]+$", "", g["ticket"])
    by_prefix.setdefault(pre, {"CRIT":0,"HIGH":0,"MED":0,"LOW":0})
    by_prefix[pre][g["sev"]] += 1

lines = []
lines.append("# GAPS — Consolidated Second-Pass Remediation Plan\n")
lines.append("Generated from the as-built gap audit of every ticket (`docs/tickets/gaps/<TICKET>.md`).")
lines.append("Each CRIT/HIGH item also has its own actionable ticket in `docs/tickets/gap-tickets/GAP-NNNN-*.md`.")
lines.append("Security findings are tracked separately as SEC-001..025; the detection/response build-out as SECOPS-001..007.\n")
lines.append("## Tally\n")
lines.append(f"- **CRIT**: {tally.get('CRIT',0)}  ·  **HIGH**: {tally.get('HIGH',0)}  ·  **MED**: {tally.get('MED',0)}  ·  **LOW**: {tally.get('LOW',0)}")
lines.append(f"- **Actionable GAP tickets created (CRIT+HIGH)**: {len(actionable)}  (GAP-0001 … GAP-{len(actionable):04d})")
lines.append(f"- **Unbuilt features** (full write-ups in `writeups/`): {len(unbuilt)} — {', '.join(unbuilt)}\n")

lines.append("## CRITICAL — fix first\n")
lines.append("| GAP | Source | Title | Location | Fix |")
lines.append("|-----|--------|-------|----------|-----|")
for g in gaps:
    if g["sev"] != "CRIT":
        continue
    lines.append(f"| {g.get('gid','')} | {g['ticket']} | {g['title'].replace('|','/')} | `{g['fileref']}` | {g['fix'].replace('|','/')[:140]} |")

lines.append("\n## HIGH — by area\n")
cur = None
for g in gaps:
    if g["sev"] != "HIGH":
        continue
    pre = re.sub(r"-[0-9]+$", "", g["ticket"])
    if pre != cur:
        cur = pre
        lines.append(f"\n### {pre}\n")
    lines.append(f"- **{g.get('gid','')}** [{g['ticket']}] {g['title']} — `{g['fileref']}` — Fix: {g['fix'][:160]}")

lines.append("\n## MED / LOW backlog (by ticket)\n")
lines.append("Counts per ticket; details in each `docs/tickets/gaps/<TICKET>.md`.\n")
lines.append("| Area | CRIT | HIGH | MED | LOW |")
lines.append("|------|------|------|-----|-----|")
for pre in sorted(by_prefix):
    c = by_prefix[pre]
    lines.append(f"| {pre} | {c['CRIT']} | {c['HIGH']} | {c['MED']} | {c['LOW']} |")

lines.append("\n## Unbuilt features (greenfield — design write-ups ready)\n")
for t in unbuilt:
    lines.append(f"- **{t}** — see `docs/tickets/writeups/{t}.md`")

with open(os.path.join(ROOT, "docs/tickets/GAPS.md"), "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"gaps parsed: {len(gaps)}  (CRIT {tally.get('CRIT',0)}, HIGH {tally.get('HIGH',0)}, MED {tally.get('MED',0)}, LOW {tally.get('LOW',0)})")
print(f"GAP tickets emitted: {len(actionable)}")
print(f"unbuilt: {len(unbuilt)}")
