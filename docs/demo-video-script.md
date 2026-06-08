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

Beyond one-to-one social, the platform has spaces built for whole communities. A group like the
Atelier Collective gets its own header, its own membership, and a dedicated feed. The header shows
the member count and quick links to everything the group shares — settings, fundraising, and a
group treasury — all in one place.

Inside the feed, admins keep the important things visible. Pin the most important updates — rules,
schedules, announcements — and they stay locked to the top of the feed for every member, marked
with a Pinned badge, no matter how much new activity comes in.

Every group also has a shared treasury — a pooled balance funded by its members. The balance card
tracks everything: what's been contributed, what's been donated, and what's been spent. Members
chip in straight from their wallet — pick an amount and tap Contribute, and it's added to the pool
instantly. Here the treasury climbs from a hundred and fifty dollars to two hundred the moment the
contribution lands.

For creators, syndicates take this even further. A syndicate is a collective — multiple creators
banding together into one group. The real power is in bundle subscriptions: a single All-Access
Bundle plan, one monthly price, and subscribers get access to every creator in the syndicate at
once. And membership is dynamic — as creators join or leave the syndicate, every bundle
subscriber's access updates automatically.

That's groups and syndicates. Next up: subscriptions and monetization.

## SEGMENT 07 — Subscriptions & Monetization

This is where the platform turns an audience into a living. It's a full money loop — fans subscribe,
creators earn, and the platform pays out.

It starts with subscriptions. The Subscriptions page lets anyone browse a creator's plans and manage
their own — all in one place. Pull up a creator and their plans appear as clean cards: each one
shows its name, a transparent monthly price, the billing interval, and any perks the creator
includes. Here it's the Studio Supporter plan at nine ninety-nine a month.

Subscribing is one tap. The moment you subscribe, billing starts and the creator's members-only
content unlocks — and the subscription shows up instantly under My Subscriptions, with its full
billing detail: the price, the active status, the renewal date, and every invoice, all tracked for
you.

Now flip to the other side of that transaction — the creator. The earnings dashboard shows lifetime
earnings across every revenue stream on the platform, and an available balance: everything past the
hold period that's ready to withdraw. The earnings breakdown shows exactly where the money comes
from — subscriptions, tips, and unlocks, each with its own share of the chart. Subscriptions are the
biggest slice.

Cashing out is just as simple. In the Request Payout form, choose an amount — the form validates it
against your available balance and the minimum — and submit. The request lands in your payout
history as "requested," awaiting review, because every payout is checked by the platform before it's
paid.

That review happens here, on the admin side. An admin sees every pending payout across all creators
in the payout queue — creator, amount, method, and status. One click to approve releases the funds,
and the status flips to "approved" — the payout is on its way.

Subscribe, earn, withdraw, approve — that's the complete monetization loop. Next up: the Shop.

## SEGMENT 08 — Shop

The platform ships with a complete storefront — so creators can sell physical merch and digital goods
right alongside everything else.

It starts in the Shop. Products are laid out as clean cards, each one organized into a browsable
category and showing its name, an image, and a price up front — the Signed Poster, the Studio Hoodie
at fifty-nine dollars, a Sticker Pack, a Preset Bundle. Tap any product to open its full detail page,
choose a quantity, and add it to your cart. The moment you do, a confirmation pops up — the item is in
your cart.

The Cart pulls it all together. Every line item appears with its thumbnail, unit price, and quantity,
and the total updates the instant you change anything — here, three items for ninety-two dollars. One
button takes you to a secure checkout.

Checkout opens with an order summary that itemizes exactly what you're buying. Got a discount code?
Apply it right here. Entering the code knocks the discount straight off the order total — twenty-five
percent off drops ninety-two dollars to sixty-nine. Then pick a payment method — a saved Visa ending
in 4242 — and place the order at the discounted total. One tap.

And if a shopper leaves a cart behind, they're not lost: the platform can email them a one-tap
recovery link to bring them right back to their cart.

Catalog, cart, promo codes, checkout, and recovery — a full e-commerce flow, built in. Next up: Files
and Integrations.

## SEGMENT 09 — Files & Integrations

Every account comes with a full cloud drive built right in — a File Manager for storing, organizing,
and previewing your files, folders and all.

Your files live in a familiar tree. Each one shows its type, its size, and the date it was last
modified — a quarterly report, your brand guidelines, an invoice, meeting notes. It's exactly the
file experience you'd expect, with none of the setup.

Finding anything is instant. By default you search by file name, and results filter as you type. But
flip the toggle and you can search inside file contents, too — the same box, two modes. Type a query
and the matching file surfaces in milliseconds. And when you've got something new to add, uploading is
one click — or just drag and drop files straight onto the page.

The File Manager doesn't stop at what you store here. Connect your Google Drive and you can browse and
import files from there without leaving the platform. The integration starts disconnected and stays
read-only until you opt in, through a secure, one-tap OAuth consent flow. Once it's connected, a
built-in picker lists your Drive files and folders — a contract draft, a headshot, a shared folder —
so you can pull any of them straight into your drive.

Files are also where documents get signed. Open the signing workspace and the platform composes a
signature packet from any PDF — and it's not a placeholder, it's the real document, rendered live in
your browser with the signature fields overlaid exactly where they belong. Senders place those fields
and route the packet to signers; assigned recipients get a guided fill workflow right here. And signing
is hands-on: a freehand pad captures a real, hand-drawn signature — or type it instead — and either way
the platform records a tamper-evident audit trail of who signed what, and when.

A cloud drive, full-text search, Google Drive integration, and built-in PDF signing — your documents,
end to end. Next up: Calendar and Booking.

## SEGMENT 10 — Calendar & Booking

Scheduling is built right in. The Calendar gives you a full month grid with your events laid out at a
glance — a product demo, a one-on-one, a standup, a design review, a client call — each one on the day
it belongs. And it's not month-only: switch between Month, Week, and Day with a single click. The week
view drops you into an hour-by-hour grid, so you can see exactly when your time is booked.

Every event is interactive. Click one and its full details open right up — the title, the description,
the start and end times, and recurrence options — all editable in place, so adjusting your schedule
never means leaving the calendar.

When you want others to schedule time with you, booking links do the work. Publish a shareable link —
a thirty-minute meeting, say — and anyone with it can pick an open slot on your calendar. Available
times are computed automatically from your calendar and your working hours, so the slots people see are
always the ones you can actually take.

And every event has a public face. Share its link and anyone can view the details without signing in —
no account required. From there it's one tap to book: visitors add the event straight to their own
calendar. Or they can download a standard dot-i-c-s file and drop it into Apple Calendar, Google
Calendar, or Outlook — full iCal export, so your events travel anywhere.

Events, scheduling, public booking, and iCal export — a complete calendar without bolting on a third
service. Next up: Tickets and Helpdesk.

## SEGMENT 11 — Tickets & Helpdesk

When something goes wrong, support is built right in. The Support Tickets page is the hub: open, track,
and resolve every customer issue, in a list or on a kanban board. For admins it's a full queue — every
ticket in one place, with live counts across Open, In progress, Waiting on user, and Unassigned.

Raising a ticket takes seconds. Anyone can file one from the New ticket form — just a subject and a
description, with validation keeping it short and clear. Hit create and the ticket is filed and threaded
instantly, opening in its own reply panel ready for a conversation.

This is where admins go to work. From the thread, assign a ticket to a teammate, claim it yourself,
resolve it, or reopen it. Here a billing dispute — an invoice charged twice — has been claimed by an
admin and worked all the way to resolution. Every status change, from assign to resolve to reopen, is
tracked end to end, so nothing falls through the cracks.

Tickets don't have to live in one big pile. Ticket Spaces let you group them into private or shared team
boards — a Billing Disputes space, for instance — and invite owners, editors, and viewers to collaborate
on a queue together.

And for the moments that call for a real conversation, there's live helpdesk chat. Customers reach out
from their own Support Chats, talking to support in real time — and every chat is bridged straight into
the agent queue. Starting a new one is a single tap on Contact Support, anytime.

Support tickets, an admin queue, shared spaces, and live helpdesk chat — a complete support desk, no
extra tooling required. Next up: KYC.

## SEGMENT 12 — KYC

Regulated platforms need to know who their users are — and the platform ships a full identity-verification
stack, end to end. Start with the applicant's view. From their Verification Status page, a user tracks
their KYC case from submission all the way to a decision: a clear timeline runs submitted, under review,
approved, with a live status badge — and an estimated review time so they always know roughly how long
it'll take.

Now switch to the reviewer. The KYC review queue puts every pending case in one place, filterable by
status, risk tier, or assignee. Each row shows the applicant, the case status, its risk tier, how long
it's been waiting, and who it's assigned to — so nothing sits unreviewed. This case is an enhanced-profile
application flagged high-risk and under active review.

Open it and you get a full review workspace. The document viewer lets a reviewer inspect every uploaded
document — ID front, ID back, and selfie — and zoom, rotate, or go fullscreen to scrutinize an ID up
close. Each document carries its own verified, pending, or rejected state. The Document Extraction tab
shows what OCR pulled from each one — name, document number, date of birth, expiry — and cross-checks
every field for a match, with an overall confidence score the reviewer can trust.

Identity verification isn't just paperwork. The verification call panel lets a reviewer schedule a live
liveness call, conduct it, and record a pass or fail outcome — tracked end to end right alongside the
documents.

And the sensitive data stays sensitive. The Sensitive PII tab keeps the document number, date of birth,
and tax ID encrypted at rest and masked by default. Revealing a field requires a reason and is logged to
an audit trail — the plaintext is shown only after that reasoned, recorded reveal.

With everything in hand, the reviewer makes the call. Approve, reject, or request more information — every
decision is reason-coded with a note. Confirm an approval and the case transitions to approved, and the
applicant is notified instantly.

Zoom out, and the KYC Metrics dashboard tells the compliance story at a glance: funnel counts across the
whole pipeline, an approval rate, and review-latency percentiles — p50, p90, and p99 — so the team can
track throughput and turnaround over time. Identity verification, documents, liveness, risk scoring, and
audited PII — a complete KYC pipeline, built in. Next up: the Ads Platform.

## SEGMENT 13 — Ads Platform

The platform isn't just a place to spend money — it's a place to make it. Built right in is a complete,
self-serve advertising platform, and it starts on the advertiser's side. From the Advertiser Dashboard,
anyone can spin up an advertiser account — here, Lumina Studios — with its own spend balance and lifetime
spend. Accounts don't go live automatically: each one is reviewed by the platform first, and this one is
approved and active.

With an account approved, advertisers build campaigns. The campaign manager shows each campaign with its
objective, a daily budget, and a lifecycle status — our Summer Launch campaign runs on an awareness
objective with a five-hundred-dollar daily budget, approved and serving.

Campaigns are filled with creatives. The creative manager handles image, video, and native-post ads —
each one uploaded, content-policy reviewed, and assigned a rotation weight. Our Hero Banner has been
uploaded and approved for delivery, and a live preview shows exactly how the ad will render before it ever
goes out.

Great ads find the right audience. The targeting editor lets advertisers dial in who sees an ad —
demographics, geography, devices, content categories, and even specific creators, with exclusions
supported too. Our saved set targets US and Canadian adults aged twenty-five to forty-four on mobile and
desktop, and a live audience estimate updates in real time as the targeting tightens or widens.

Ads don't only run in the feed — they run inside live broadcasts. When a non-subscribing viewer joins a
live stream, they're served a skippable in-stream pre-roll ad before playback begins, complete with a
sponsored label and a five-second skip timer. Subscribers, of course, join completely ad-free.

And every dollar is measured. The advertiser analytics dashboard reports impressions, clicks, click-through
rate, spend, and cost-per-acquisition — the figures that drive return on ad spend — with daily performance
trends and per-creative and per-surface breakdowns underneath.

Finally, the platform keeps control of its own ad ecosystem. The root-only Ad Platform Management console
gives operators cross-account oversight — moderation, revenue, and, under Emergency Controls, a
platform-wide ad kill-switch. A single, reason-gated, audited control can halt all ad serving instantly,
with a live status badge showing whether ads are serving normally or fully halted. Advertiser accounts,
campaigns, creatives, targeting, in-stream ads, analytics, and a platform kill-switch — a full ads stack,
built in. Next up: VOD.

## SEGMENT 14 — Video on Demand

Beyond live broadcasts, the platform is a full video-on-demand service — and it begins in the creator's
video library. Every upload, every transcode, and every published title lives here in one catalog. This
one, "Behind the Build — Episode 1," is finished and published as adaptive-bitrate HLS, ready to stream,
with its lifecycle status shown right on the card — uploading, encoding, in review, or ready.

Getting there runs through a pipeline. When a creator uploads a file, the platform probes it, encodes it
into multiple HLS renditions, and then drops it into a review queue. The admin Video Review Queue is where
those freshly transcoded videos wait — each one approved or rejected before it can ever publish.

Once it's live, playback is locked down. The player streams real adaptive-bitrate HLS, but it only plays
because the platform issued a short-lived, per-session playback token — and that token quietly refreshes
mid-stream so long sessions never stall. Multiple renditions are encoded per video, so the stream adapts to
whatever bandwidth the viewer has.

Look closely at the picture and you'll see a second layer of protection: a forensic session watermark. A
faint, repeating fingerprint — the viewer's session token plus the creator's tenant ID — is drawn across
every single frame, so if a recording ever leaks, it traces straight back to the session that made it.

Underneath that sits tenant-scoped DRM. The HLS segments are AES-128 encrypted, and the keys are minted
per-tenant and released only to a valid, entitled token. The encrypted files alone are worthless — without
the tenant key, a leaked segment plays back as nothing. And before a key is ever issued, access itself is
checked: free, subscriber-only, or pay-per-view, the entitlement is verified up front.

Creators can also cut highlights into shareable clips. This public clip page needs no login at all — anyone
with the link can watch — and every clip stays attributed, linking back to the original broadcast and
crediting the creator who made it.

Finally, when downloads are allowed, they're protected too. The download is minted on demand with a
per-viewer forensic watermark burned directly into the file. Upload, a transcode pipeline, token-gated and
watermarked playback, tenant DRM, clips, and protected downloads — a complete VOD stack. Next up: remote
terminals.

## SEGMENT 15 — Remote Terminals

The platform doesn't just manage content — it gives you remote access to your infrastructure, straight from
the browser. It starts with the host inventory: one place to save every machine you connect to. SSH servers,
VNC desktops, and RDP boxes all live here, grouped by environment, so production, staging, and support stay
tidy and easy to find. Each row shows the label, the hostname and port, and a protocol badge at a glance —
and a VNC support desktop sits right alongside the SSH servers in the same list. When you want in, the plug
icon is a one-click quick-connect: it launches a brokered session straight into the browser terminal, with
no client to install.

Take VNC first. The noVNC connection form brokers a session entirely in the browser — you give it a target,
and the platform validates it and opens a secure viewer. And notice the auth-input mode: you can connect with
a short-lived session token, or a one-off password that is never persisted. Secrets stay safe by design.

SSH adds another option: stored-key authentication. You generate or upload a key once, here in the key
manager, and from then on your connections just reference it by id. The private key lives encrypted on the
server and is resolved at connect time — the PEM never reaches the browser at all.

For locked-down hosts that you can't reach directly, there's the multi-hop bastion. You define an ordered
chain of jump hosts that the platform tunnels through to a target. Here, the production database is only
reachable through a public bastion — and the path shows the whole route end to end: platform, to the bastion,
to the final target. One click connects through every hop, all from the browser.

And everything you do is captured. Every SSH session is recorded server-side as an asciicast — host, user,
duration, and size — for a tamper-evident audit trail. This one was recorded off the prod-web-1 host as
ubuntu, and you can replay the entire terminal transcript right in the browser: scrub through every command
and its output, with no external tooling, fully auditable. Host inventory, brokered VNC and SSH, stored-key
auth, multi-hop bastions, and recorded sessions — full remote access, all in the browser. Next up: admin and
root.

## SEGMENT 16 — Admin & Root

Behind every platform is a set of controls only the people running it should ever touch — and this is where
they live. We're filming as the root account, the one identity that sees every control. It starts with the
root-only role console: this is where you assign admins, tune their capability profiles, and review an
immutable audit history. Granting a role is a deliberate, reason-required action — you can promote someone to a
general admin with the run of every domain, or a scoped admin confined to just auth, billing, or content
moderation. And you can re-scope an existing admin between general and scoped, or revoke the role entirely.
Whatever you do, it lands in the role-assignment audit timeline: every grant, revoke, and profile change,
recorded with the actor, the target, and the reason.

Support teams sometimes need to see exactly what a user sees — so impersonation is built right in. A persistent
banner lets root and general admins act as another user, but only after entering a target and a reason, and the
session expires automatically. Once you begin, the banner switches to show exactly who you're acting as and
when it expires — it stays visible the whole time you're impersonating, so there's never any doubt. One click
on Stop returns you to your own account, and the session and its full audit trail are sealed.

Keeping the platform safe is a daily job, so there's a dedicated moderation board. Reported content flows into
newsfeed, message, and profile queues that you can filter by status, topic, and assignee. Open any ticket and
you get the full picture: a snapshot of the content, the linked reports, the offender's history, and prior
enforcement actions. Then you decide — resolve it as no-violation or content-removed, with an optional warn or
ban enforcement action, all in one panel.

When auditors come calling, the audit log export has you covered. Pull events by category — auth, moderation,
broadcast, admin, billing — and export them as machine-readable NDJSON or CSV, or as a tamper-evident,
audit-grade PDF. Past exports are listed with their status, event count, and a download link, and recurring
reports can run automatically on a schedule.

Money needs its own watchtower, and that's the payment provider health dashboard. Stripe, PayPal, and CCBill
are tracked live — success rate, average and p95 latency, success and failure counts, and the last health
check, all at a glance, with full incident history behind it. And when a provider goes sideways, root has a
kill-switch: disabling a provider stops new payment initiation instantly, while in-flight charges are left
untouched. Even that is reason-gated — flipping the switch is a deliberate, logged decision. Zoom out to the
platform financials and you get the bird's-eye view: revenue trends over time and a provider split across all
three processors. Roles, impersonation, moderation, audit exports, payment health, and kill-switches — the
complete operator toolkit. Next up: compute.

## SEGMENT 17 — Compute
<!-- TODO -->
