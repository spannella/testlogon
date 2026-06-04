# SECOPS-003: Honeypots & Honeytokens (canaries)

**Ticket**: SECOPS-003 · **Status**: Open · **Priority**: Medium-High · **Date**: 2026-06-04
**Theme**: Security Detection & Response. **Emits to**: SECOPS-001; **triggers**: SECOPS-002 auto-ban.

## Goal
Bait that legitimate users never touch, so any interaction is **high-confidence
malicious** → immediate log + auto-block. Cheap, very low false-positive signal.

## Design
- **Decoy routes** (`app/routers/honeypot.py`): serve plausible-but-fake responses for
  paths scanners hammer — `/wp-login.php`, `/wp-admin`, `/.env`, `/.git/config`,
  `/phpmyadmin`, `/admin.php`, `/actuator/env`, `/api/v1/debug`, `/server-status`,
  `/.aws/credentials`. Any hit → `honeypot.hit` (SECOPS-001) + auto-ban candidate.
  (Must NOT collide with the SPA catch-all; register before it.)
- **Honeytokens / canary records**: seed decoy artifacts a normal user never accesses —
  a fake "admin" user, a canary KYC case, a canary file in the file manager, a fake
  payment method, a planted **API key string** that, if ever presented, fires
  `honeytoken.used`. Catches IDOR enumeration (SEC-005) and stolen-credential use
  (SEC-022): e.g. reading the canary record by id ⇒ someone is walking IDs.
- **Form/param traps**: a hidden, CSS-invisible form field ("website"/"company") that
  only bots fill → flag on submit; an unused but tempting query param.
- **Canary identifiers**: a sequential/guessable decoy id range that no real client
  requests; access ⇒ enumeration in progress.
- **Response strategy**: keep decoys realistic (don't reveal they're traps); optionally
  tarpit flagged sources (SECOPS-002). Make the canary set seedable for tests and
  configurable so prod canaries aren't in the repo verbatim.

## Testing
pytest/E2E: hitting `/.env` or `/wp-login.php` emits `honeypot.hit` and (with auto-ban
on) blocks the source; reading a canary record/using a canary token emits
`honeytoken.used`; the hidden-field trap flags a submission; real users/flows never
trip a honeypot (no false positives in the E2E suite).
