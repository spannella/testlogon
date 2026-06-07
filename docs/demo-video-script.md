# Demo walkthrough — voiceover script

Narration for the 30-minute feature-walkthrough video. One `## SEGMENT NN` block per
segment; `scripts/render_voiceover.py` renders each block to `frontend/e2e/demo/out/voiceNN.mp3`
via ElevenLabs and concatenates them into `out/voiceover.mp3`, which is then muxed onto
`out/demo_walkthrough.mp4`.

**Alignment:** each block's spoken length should roughly match its segment's video length
(≈ Σ of the segment's `beat()`s). After rendering, compare `ffprobe` durations and tune the
segment's beats (or split narration) so audio and video line up. Keep sentences short and
declarative — they track the on-screen caption banners.

**Conventions:** plain prose only (no stage directions in the spoken text); write numbers/acronyms
as they should be *said* ("K-Y-C", "single sign-on") where TTS would mangle them.

---

## SEGMENT 01 — Authentication & Onboarding

Welcome to a guided tour of the platform — a full-stack creator and commerce platform with
messaging, media, monetization, and a complete admin back office. Let's start by signing in.

Authentication is built on secure, cookie-based sessions with cross-site request forgery
protection, backed by Cognito-issued JSON web tokens. Users sign in with a password, a one-time
email link, or a hardware security key.

Once signed in, you land on a personalized dashboard — recent activity, messages, billing, and
quick actions, all in one place.

Every account has a dedicated security center. Members can enroll authenticator apps for
multi-factor authentication and download recovery codes. They can register passkeys for
hardware-backed, phishing-resistant sign-in. They can mint scoped, peppered API keys for
programmatic access — and review and revoke every active session from any device. Security first,
everywhere.

Next up: real-time messaging.

---

## SEGMENT 02 — Messaging
<!-- TODO after seg02 is recorded -->

## SEGMENT 03 — Calls
<!-- TODO -->

## SEGMENT 04 — Newsfeed
<!-- TODO -->

## SEGMENT 05 — Social
<!-- TODO -->

## SEGMENT 06 — Groups & Syndicates
<!-- TODO -->

## SEGMENT 07 — Subscriptions & Monetization
<!-- TODO -->

## SEGMENT 08 — Shop
<!-- TODO -->

## SEGMENT 09 — Files & Integrations
<!-- TODO -->

## SEGMENT 10 — Calendar & Booking
<!-- TODO -->

## SEGMENT 11 — Tickets & Helpdesk
<!-- TODO -->

## SEGMENT 12 — KYC
<!-- TODO -->

## SEGMENT 13 — Ads Platform
<!-- TODO -->

## SEGMENT 14 — VOD
<!-- TODO -->

## SEGMENT 15 — Remote Terminals
<!-- TODO -->

## SEGMENT 16 — Admin & Root
<!-- TODO -->

## SEGMENT 17 — Compute
<!-- TODO -->
