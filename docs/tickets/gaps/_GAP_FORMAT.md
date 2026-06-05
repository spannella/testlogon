# Gap entry format (one file per ticket: gaps/<TICKET>.md)

Each line is one discovered gap/bug/security issue from the as-built review:

- [SEV] <short title> — `file:line` — <impact in 1 line> — Fix: <1-line fix> — Effort: S|M|L

SEV ∈ CRIT | HIGH | MED | LOW. If a ticket is genuinely UNBUILT, write a single line:
- [UNBUILT] feature not implemented — see writeups/<TICKET>.md
