# SEC-014: Notification / SMS Toll-Fraud / Email Phishing-Relay

**Ticket**: SEC-014 · **Status**: Open · **Priority**: Critical · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 3)

## Problem
Verification codes are sent to **attacker-supplied destinations before ownership is
proven**, enabling toll fraud, harassment, and using your domain as a phishing/spam relay:
- `app/routers/mfa_devices.py:108-142` (SMS begin) — enroll ANY `phone_e164`; sends
  SMS code to that number (+ existing) with only a per-user rate limit → **SMS pumping/
  toll fraud** + harass arbitrary numbers.
- `:230-267` (email begin) — enroll ANY email; sends a code there → **phishing relay**
  from your sending domain.
- `:171-196` / `:296-323` (removal-challenge) — repeatable SMS/email to linked
  destinations → spam.
- `register.py:273` — registration SMS to arbitrary `body.phone` for any email.
- Twilio Verify path (`mfa.py:81`) **bypasses** `sms_daily_limit_per_number`
  (`sms_delivery.py:331`); no per-recipient (cross-account) cap on email/SMS.
- Enumeration: resend/reset/magic-link reveal whether an email/phone is registered.

## Fix
- **Prove ownership before sending to a new destination is even allowed**, or at least:
  cap distinct phone numbers/emails enrolled per user per window; enforce the
  per-number daily cap on **all** SMS sends incl. Twilio Verify; add a **per-recipient
  (global) cap** on verification SMS/email; backoff.
- Don't relay attacker-controlled body/links in emails sent to others; recipients of
  notification/invite emails should be verified.
- Normalize resend/reset/magic-link responses (no enumeration); rate-limit per IP+target.

## Testing
pytest: enrolling >N distinct numbers/emails per window is blocked; per-number daily
cap applies to Verify; sending the same recipient repeatedly across accounts is capped;
resend for unknown vs known address is indistinguishable.
