/**
 * E2E Tests for Video Sharing in Messages
 *
 * Sections:
 *   124 — Video Share API (DM) (8 tests)
 *   125 — Video Share in Group Chat (3 tests)
 *   126 — Conversation Preview After Video Share (2 tests)
 *
 * Auth: Cookie sessions via e2e_admin_session_setup.py
 * Identities: alice (USER), bob (USER), charlie_admin (ADMIN)
 *
 * Videos are seeded directly in DynamoDB to avoid needing a full transcode
 * pipeline. The video_share message endpoint validates ownership + status.
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";

// ─── Constants ────────────────────────────────────────────────────────────────

const API = "http://localhost:8000";
const BASE = "http://localhost:3000";
const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const CHARLIE_ID = "e2e_charlie@test.local";
const TS = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string;
    value: string;
    domain: string;
    path: string;
    httpOnly: boolean;
    secure: boolean;
    sameSite: "Lax" | "Strict" | "None";
    expires: number;
  }>;
}

let _sessions: Record<string, SessionData> | null = null;
function getSessions(): Record<string, SessionData> {
  if (!_sessions) {
    const raw = execSync(
      "python3 /home/ubuntu/testlogon/e2e_admin_session_setup.py",
      { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
    ).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for identity "${identity}"`);
  await page.context().addCookies(session.cookies);
}

async function apiPost(page: Page, identity: string, path: string, body: object = {}) {
  const s = getSessions()[identity];
  return page.request.post(`${API}${path}`, {
    data: body,
    headers: { "x-csrf-token": s.csrf_token },
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(`${API}${path}`);
}

// ─── DynamoDB helpers ─────────────────────────────────────────────────────────

function seedVideo(opts: {
  videoId: string;
  ownerUserId: string;
  title: string;
  status?: string;
  visibility?: string;
  hlsManifestUrl?: string;
  thumbnailUrl?: string;
}): void {
  const status = opts.status ?? "published";
  const visibility = opts.visibility ?? "public";
  const createdAt = Math.floor(Date.now() / 1000);
  const hlsField = opts.hlsManifestUrl
    ? `'hls_manifest_url': '${opts.hlsManifestUrl}',`
    : "";
  const thumbField = opts.thumbnailUrl
    ? `'thumbnail_url': '${opts.thumbnailUrl}',`
    : "";
  const publishedField = status === "published" ? `'published_at': ${createdAt},` : "";

  const script = `
import sys, os
sys.path.insert(0, '/home/ubuntu/testlogon')
os.environ.setdefault('DDB_ENDPOINT_URL', 'http://localhost:8001')
os.environ.setdefault('AWS_ACCESS_KEY_ID', 'test')
os.environ.setdefault('AWS_SECRET_ACCESS_KEY', 'test')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
import boto3
from decimal import Decimal
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1')
table = ddb.Table('VideoMetadata')
table.put_item(Item={
    'video_id': '${opts.videoId}',
    'owner_user_id': '${opts.ownerUserId}',
    'title': '${opts.title}',
    'status': '${status}',
    'visibility': '${visibility}',
    'created_at': ${createdAt},
    'updated_at': ${createdAt},
    'source_type': 'upload',
    'duration_seconds': Decimal('120.5'),
    'width': 1920,
    'height': 1080,
    ${hlsField}
    ${thumbField}
    ${publishedField}
})
print('ok')
`;
  execSync(
    `/home/ubuntu/testlogon/.venv/bin/python3 -c "${script.replace(/"/g, '\\"')}"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
  );
}

function deleteVideo(videoId: string): void {
  const script = `
import sys, os
sys.path.insert(0, '/home/ubuntu/testlogon')
os.environ.setdefault('DDB_ENDPOINT_URL', 'http://localhost:8001')
os.environ.setdefault('AWS_ACCESS_KEY_ID', 'test')
os.environ.setdefault('AWS_SECRET_ACCESS_KEY', 'test')
os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
import boto3
ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1')
ddb.Table('VideoMetadata').delete_item(Key={'video_id': '${videoId}'})
print('ok')
`;
  try {
    execSync(
      `/home/ubuntu/testlogon/.venv/bin/python3 -c "${script.replace(/"/g, '\\"')}"`,
      { cwd: "/home/ubuntu/testlogon", timeout: 10_000 },
    );
  } catch {
    /* ignore cleanup errors */
  }
}

function seedConversation(opts: {
  conversationId: string;
  participantIds: string[];
  type?: string;
  name?: string;
}): void {
  const type = opts.type ?? "dm";
  const nameField = opts.name ? `'name': '${opts.name}',` : "";
  const py = `
import boto3, time
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test",
                     aws_secret_access_key="test")
table = ddb.Table("Conversations")
ts = int(time.time())
table.put_item(Item={
    "conversation_id": ${JSON.stringify(opts.conversationId)},
    "participant_ids": ${JSON.stringify(opts.participantIds)},
    "type": "${type}",
    ${nameField}
    "created_at": ts,
    "last_message_at": ts,
    "updated_at": ts,
})
ptable = ddb.Table("Participants")
for uid in ${JSON.stringify(opts.participantIds)}:
    ptable.put_item(Item={
        "user_id": uid,
        "conversation_id": ${JSON.stringify(opts.conversationId)},
        "status": "active",
        "joined_at": ts,
    })
print("ok")
`;
  execSync(`python3 -c '${py.replace(/'/g, "'\\''")}'`, {
    cwd: "/home/ubuntu/testlogon",
    timeout: 10_000,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
  });
}

// ─── State shared across sections ────────────────────────────────────────────

let alicePage: Page;
let bobPage: Page;
let charliePage: Page;

test.beforeAll(async ({ browser }) => {
  const aliceCtx = await browser.newContext();
  alicePage = await aliceCtx.newPage();
  await injectAuth(alicePage, "alice");
  await alicePage.goto(BASE);

  const bobCtx = await browser.newContext();
  bobPage = await bobCtx.newPage();
  await injectAuth(bobPage, "bob");
  await bobPage.goto(BASE);

  const charlieCtx = await browser.newContext();
  charliePage = await charlieCtx.newPage();
  await injectAuth(charliePage, "charlie_admin");
  await charliePage.goto(BASE);
});

test.afterAll(async () => {
  await alicePage?.context().close();
  await bobPage?.context().close();
  await charliePage?.context().close();
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 124 — Video Share API (DM)
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("124 — Video Share API (DM)", () => {
  const CONVO_ID = `vs_dm_${TS}`;
  const ALICE_PUB_VID = `v_${TS.toString(16).padStart(13, "0")}a100000000000000000`;
  const ALICE_UNPUB_VID = `v_${TS.toString(16).padStart(13, "0")}a200000000000000000`;
  const BOB_PUB_VID = `v_${TS.toString(16).padStart(13, "0")}b100000000000000000`;
  const BOB_PRIV_VID = `v_${TS.toString(16).padStart(13, "0")}b200000000000000000`;

  const ALICE_SUB = () => getSessions().alice.user_sub;
  const BOB_SUB = () => getSessions().bob.user_sub;

  test.beforeAll(() => {
    // Create DM conversation
    seedConversation({
      conversationId: CONVO_ID,
      participantIds: [ALICE_ID, BOB_ID],
    });

    // Alice's public published video
    seedVideo({
      videoId: ALICE_PUB_VID,
      ownerUserId: ALICE_SUB(),
      title: `Alice Public Video ${TS}`,
      status: "published",
      visibility: "public",
      hlsManifestUrl: `https://cdn.example.com/hls/${ALICE_PUB_VID}/manifest.m3u8`,
      thumbnailUrl: `https://cdn.example.com/thumb/${ALICE_PUB_VID}.jpg`,
    });

    // Alice's unpublished (draft) video
    seedVideo({
      videoId: ALICE_UNPUB_VID,
      ownerUserId: ALICE_SUB(),
      title: `Alice Unpublished Video ${TS}`,
      status: "created",
      visibility: "private",
    });

    // Bob's public published video
    seedVideo({
      videoId: BOB_PUB_VID,
      ownerUserId: BOB_SUB(),
      title: `Bob Public Video ${TS}`,
      status: "published",
      visibility: "public",
      hlsManifestUrl: `https://cdn.example.com/hls/${BOB_PUB_VID}/manifest.m3u8`,
    });

    // Bob's private published video
    seedVideo({
      videoId: BOB_PRIV_VID,
      ownerUserId: BOB_SUB(),
      title: `Bob Private Video ${TS}`,
      status: "published",
      visibility: "private",
    });
  });

  test.afterAll(() => {
    deleteVideo(ALICE_PUB_VID);
    deleteVideo(ALICE_UNPUB_VID);
    deleteVideo(BOB_PUB_VID);
    deleteVideo(BOB_PRIV_VID);
  });

  test("124.1 Alice shares her published video in DM → 200, kind=video_share", async () => {
    const resp = await apiPost(alicePage, "alice", `/messaging/conversations/${CONVO_ID}/messages/video-share`, {
      video_id: ALICE_PUB_VID,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.kind).toBe("video_share");
    expect(data.video_share).toBeTruthy();
  });

  test("124.2 video_share response has title and video_id", async () => {
    const resp = await apiPost(alicePage, "alice", `/messaging/conversations/${CONVO_ID}/messages/video-share`, {
      video_id: ALICE_PUB_VID,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.video_share.video_id).toBe(ALICE_PUB_VID);
    expect(data.video_share.title).toBe(`Alice Public Video ${TS}`);
  });

  test("124.3 Bob fetches messages → video_share includes thumbnail_url", async () => {
    // Send a video share as Alice first
    await apiPost(alicePage, "alice", `/messaging/conversations/${CONVO_ID}/messages/video-share`, {
      video_id: ALICE_PUB_VID,
    });

    // Bob fetches messages
    const msgsResp = await apiGet(bobPage, `/messaging/conversations/${CONVO_ID}/messages`);
    expect(msgsResp.status()).toBe(200);
    const messages = await msgsResp.json();
    const vsMsg = messages.find((m: { kind: string }) => m.kind === "video_share");
    expect(vsMsg).toBeTruthy();
    // thumbnail_url should be present in video_share data
    expect(vsMsg.video_share.thumbnail_url).toBeTruthy();
  });

  test("124.4 Share with caption → text field populated", async () => {
    const caption = `Check this out! ${TS}`;
    const resp = await apiPost(alicePage, "alice", `/messaging/conversations/${CONVO_ID}/messages/video-share`, {
      video_id: ALICE_PUB_VID,
      text: caption,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.text).toBe(caption);
    expect(data.kind).toBe("video_share");
  });

  test("124.5 Share unpublished (draft) video → 400", async () => {
    const resp = await apiPost(alicePage, "alice", `/messaging/conversations/${CONVO_ID}/messages/video-share`, {
      video_id: ALICE_UNPUB_VID,
    });
    expect(resp.status()).toBe(400);
  });

  test("124.6 Non-owner shares private video → 403", async () => {
    // Alice tries to share Bob's private video
    const resp = await apiPost(alicePage, "alice", `/messaging/conversations/${CONVO_ID}/messages/video-share`, {
      video_id: BOB_PRIV_VID,
    });
    expect(resp.status()).toBe(403);
  });

  test("124.7 Non-owner shares public video → 200", async () => {
    // Alice shares Bob's public video — should succeed
    const resp = await apiPost(alicePage, "alice", `/messaging/conversations/${CONVO_ID}/messages/video-share`, {
      video_id: BOB_PUB_VID,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.kind).toBe("video_share");
    expect(data.video_share.video_id).toBe(BOB_PUB_VID);
  });

  test("124.8 Share in DM with non-participant → 403", async () => {
    // Charlie is not part of this DM conversation
    const resp = await apiPost(charliePage, "charlie_admin", `/messaging/conversations/${CONVO_ID}/messages/video-share`, {
      video_id: BOB_PUB_VID,
    });
    expect([403, 404]).toContain(resp.status());
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 125 — Video Share in Group Chat
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("125 — Video Share in Group Chat", () => {
  const GROUP_CONVO_ID = `vs_group_${TS}`;
  const ALICE_SUB = () => getSessions().alice.user_sub;
  const GROUP_VID_ID = `v_vs_group_${TS}`.slice(0, 32).padEnd(32, "0").replace(/[^a-f0-9]/g, "0");

  test.beforeAll(() => {
    seedConversation({
      conversationId: GROUP_CONVO_ID,
      participantIds: [ALICE_ID, BOB_ID, CHARLIE_ID],
      type: "group",
      name: `E2E Video Share Group ${TS}`,
    });

    seedVideo({
      videoId: GROUP_VID_ID,
      ownerUserId: ALICE_SUB(),
      title: `Group Share Video ${TS}`,
      status: "published",
      visibility: "public",
      hlsManifestUrl: `https://cdn.example.com/hls/${GROUP_VID_ID}/manifest.m3u8`,
      thumbnailUrl: `https://cdn.example.com/thumb/${GROUP_VID_ID}.jpg`,
    });
  });

  test.afterAll(() => {
    deleteVideo(GROUP_VID_ID);
  });

  test("125.1 Alice shares video in group chat → 200", async () => {
    const resp = await apiPost(alicePage, "alice", `/messaging/conversations/${GROUP_CONVO_ID}/messages/video-share`, {
      video_id: GROUP_VID_ID,
      text: `Group video share ${TS}`,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.kind).toBe("video_share");
    expect(data.video_share.video_id).toBe(GROUP_VID_ID);
  });

  test("125.2 Bob (group participant) sees the video share in messages", async () => {
    const msgsResp = await apiGet(bobPage, `/messaging/conversations/${GROUP_CONVO_ID}/messages`);
    expect(msgsResp.status()).toBe(200);
    const messages = await msgsResp.json();
    const vsMsg = messages.find((m: { kind: string; video_share?: { video_id: string } }) =>
      m.kind === "video_share" && m.video_share?.video_id === GROUP_VID_ID
    );
    expect(vsMsg).toBeTruthy();
    expect(vsMsg.video_share.title).toBe(`Group Share Video ${TS}`);
  });

  test("125.3 video_share in group message includes thumbnail_url", async () => {
    const msgsResp = await apiGet(alicePage, `/messaging/conversations/${GROUP_CONVO_ID}/messages`);
    expect(msgsResp.status()).toBe(200);
    const messages = await msgsResp.json();
    const vsMsg = messages.find((m: { kind: string; video_share?: { video_id: string } }) =>
      m.kind === "video_share" && m.video_share?.video_id === GROUP_VID_ID
    );
    expect(vsMsg).toBeTruthy();
    expect(vsMsg.video_share.thumbnail_url).toBeTruthy();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Section 126 — Conversation Preview After Video Share
// ═══════════════════════════════════════════════════════════════════════════════

test.describe("126 — Conversation Preview After Video Share", () => {
  const PREV_CONVO_ID = `vs_prev_${TS}`;
  const ALICE_SUB = () => getSessions().alice.user_sub;
  const PREV_VID_ID = `v_vs_prev_${TS}`.slice(0, 32).padEnd(32, "0").replace(/[^a-f0-9]/g, "0");
  const PREV_VIDEO_TITLE = `Preview Video ${TS}`;

  test.beforeAll(() => {
    seedConversation({
      conversationId: PREV_CONVO_ID,
      participantIds: [ALICE_ID, BOB_ID],
    });

    seedVideo({
      videoId: PREV_VID_ID,
      ownerUserId: ALICE_SUB(),
      title: PREV_VIDEO_TITLE,
      status: "published",
      visibility: "public",
    });
  });

  test.afterAll(() => {
    deleteVideo(PREV_VID_ID);
  });

  test("126.1 After video share, conversation list shows preview text with video title", async () => {
    // Share the video
    const shareResp = await apiPost(alicePage, "alice", `/messaging/conversations/${PREV_CONVO_ID}/messages/video-share`, {
      video_id: PREV_VID_ID,
    });
    expect(shareResp.status()).toBe(200);

    // Fetch conversation list
    const listResp = await apiGet(alicePage, `/messaging/conversations`);
    expect(listResp.status()).toBe(200);
    const listData = await listResp.json();
    const conversations = listData.conversations ?? listData.items ?? listData;
    const convo = Array.isArray(conversations)
      ? conversations.find((c: { conversation_id: string }) => c.conversation_id === PREV_CONVO_ID)
      : null;
    expect(convo).toBeTruthy();
    // Preview text should reference the video title
    const preview = convo.last_message_preview ?? convo.preview ?? "";
    expect(preview).toContain(PREV_VIDEO_TITLE);
  });

  test("126.2 After video share with caption, preview shows caption text", async () => {
    const caption = `Watch this! ${TS}`;
    const shareResp = await apiPost(alicePage, "alice", `/messaging/conversations/${PREV_CONVO_ID}/messages/video-share`, {
      video_id: PREV_VID_ID,
      text: caption,
    });
    expect(shareResp.status()).toBe(200);

    const listResp = await apiGet(alicePage, `/messaging/conversations`);
    expect(listResp.status()).toBe(200);
    const listData = await listResp.json();
    const conversations = listData.conversations ?? listData.items ?? listData;
    const convo = Array.isArray(conversations)
      ? conversations.find((c: { conversation_id: string }) => c.conversation_id === PREV_CONVO_ID)
      : null;
    expect(convo).toBeTruthy();
    const preview = convo.last_message_preview ?? convo.preview ?? "";
    expect(preview).toContain(caption);
  });
});
