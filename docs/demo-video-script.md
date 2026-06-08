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

Now let's talk to people. Messaging is real-time — direct messages and group chats that sync
instantly between everyone in the conversation.

Here's a live thread. A two-sided history streams in the moment it's sent. Composing is simple:
type a message and fire it off, and your bubble appears right at the bottom, newest first.

But these aren't ordinary messages. Turn on view-once, and the recipient can open the message
exactly once — after they peek, the content self-destructs. Perfect for anything sensitive.

For real privacy, enable client-side encryption. The message is encrypted right here in the
browser, with AES-256-GCM and a key derived from a shared password, before it ever leaves your
device. The server only ever stores ciphertext — never the plaintext. The recipient decrypts on
demand by entering the password, and the original text appears.

Creators can monetize, too. Send a tip — real money attached to a message, with micro-payments
built right in. Or lock premium content behind a one-time payment: the recipient sees an unlock
button and pays to reveal it.

You can schedule a send to deliver automatically at a future time. And attachments go far beyond
text — images, video and PDFs with optional view-once, files shared straight from your file
manager, calendar events and meeting polls, and voice notes including listen-once.

Everything direct messages can do, group chats do too — with sender names, reactions, and the same
rich toolset for the whole team.

That's messaging. Next up: voice and video calls.

---

## SEGMENT 03 — Calls

Sometimes a message isn't enough. From any conversation you can start a call — one-to-one audio,
or flip on the camera for full video, right from the chat header.

These calls can be paid. A creator sets a per-minute rate, and that rate is shown up front, next to
the call buttons, before you ever dial. No surprises.

Place the call, and it connects to a clean in-call overlay — mute, recording, and hang-up controls,
all in one place.

Here's the part that matters: live billing. A cost ticker updates in real time, showing the running
cost, the per-minute rate, and your remaining wallet balance — right there as the call runs. If your
balance ever runs low, you get a clear warning before it ends.

When you're done, hang up, and you get a clear outcome: the call ended.

Calls can also be recorded. Every recording lands in the conversation menu, listed with its date,
duration, and size — and a one-click download whenever you need it.

That's voice and video calls. Next up: the newsfeed.

---

## SEGMENT 04 — Newsfeed

Now let's look at the newsfeed — a living timeline of your own posts and updates from the
creators you follow, all in one place.

Posts aren't just plain text. Compose a quick update, or switch to rich text and markdown —
headings, bold, lists — with a live preview as you type. One click and it's live in the feed,
right at the top of the timeline.

Every post is interactive. React with a tap — thumbs up, heart, laughing, fire, or wow — and the
counts update instantly. Open the threaded comments under any post to reply, react, edit, and
even tip individual comments.

Creators can monetize directly from the feed. Send a tip straight from any post — micro-payments
are built right in. Or lock premium content behind a one-time payment: viewers see a pay-to-unlock
button, choose a card, confirm the total, and the post reveals instantly.

Want to hear from your audience? Run a poll or survey — single or multi-choice — with live
results. Cast a vote and watch the percentages and totals fill in the moment it lands.

And anything worth keeping, you can bookmark — saved away for whenever you come back.

That's the newsfeed. Next up: social.

## SEGMENT 05 — Social

The social layer is what turns the platform into a community. Every creator gets a shareable
public profile — a clean page with their avatar, name, and headline, like Bob Rivera here, the
photographer and creator. Right in the header you get social stats at a glance: followers,
following, and post counts.

Following someone is one tap. Hit Follow and their posts start flowing into your feed — the button
flips straight to "Following," and the follower count ticks up live, from nine forty-eight to nine
forty-nine.

You're always in control of who you interact with. Every profile has a more-actions menu right next
to Follow. Open it to block someone — a blocked user can no longer message you or see your content,
and you can unblock them any time from Settings.

Finding people is just as easy. The Discover page surfaces suggested and trending creators, and
instant search lets you find anyone as you type — search "Bob" and matching creators appear right
away.

And as you grow, you earn achievements. Hit milestones to unlock badges — your First Post, Rising
Star for reaching a thousand followers, and more. Badges come in tiers, from common to rare, epic,
and legendary, each worth points toward the leaderboard, and you can showcase your favorites on
your profile.

That's the social layer. Next up: groups and syndicates.

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
