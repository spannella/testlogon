/**
 * GAP-0146: RecordingsPanel frontend component
 *
 * Verifies the in-product surface for discovering past call recordings
 * (the "Recordings" entry in the conversation menu + the slide-in panel).
 * Before the fix, no UI path existed — recording discovery relied entirely on
 * an ephemeral upload toast.
 *
 * Section 146 — Recordings panel discoverability (2 tests)
 *
 * Auth: cookie-based session auth (from e2e_admin_session_setup.py).
 * Conversation + CallRecordings rows are seeded directly in DynamoDB.
 *
 * Requires VITE_CALL_RECORDING_ENABLED=true (default in .env.local.example).
 */

import { test, expect, type Page } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const ALICE_ID = "e2e_alice@test.local";
const BOB_ID = "e2e_bob@test.local";
const TS = Date.now();

// ---------------------------------------------------------------------------
// Session bootstrap (mirrors call-recording-integration.spec.ts)
// ---------------------------------------------------------------------------

interface SessionData {
  user_sub: string;
  csrf_token: string;
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
    const raw = execSync("python3 " + REPO_ROOT + "/e2e_admin_session_setup.py", {
      cwd: REPO_ROOT,
      timeout: 30_000,
    }).toString();
    _sessions = JSON.parse(raw);
  }
  return _sessions!;
}

async function injectAuth(page: Page, identity: string) {
  const session = getSessions()[identity];
  if (!session) throw new Error(`No session for identity "${identity}"`);
  await page.context().addCookies(session.cookies);
  // ProtectedRoute gates the SPA on the persisted auth-store; cookies alone
  // authenticate API calls but the router would redirect to /login. Seed the
  // auth-store before every navigation so protected pages actually render.
  await page.addInitScript((uid: string) => {
    const state = { userId: uid, accessToken: null, isAuthenticated: true };
    localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
  }, session.user_sub);
}

// ---------------------------------------------------------------------------
// DynamoDB seeding helpers
// ---------------------------------------------------------------------------

function runPy(py: string): void {
  execSync(`python3 -c '${py.replace(/'/g, "'\\''")}'`, {
    cwd: REPO_ROOT,
    timeout: 10_000,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
  });
}

function seedConversation(conversationId: string, participantIds: string[]): void {
  runPy(`
import boto3, time
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
ts = int(time.time())
ddb.Table("Conversations").put_item(Item={
    "conversation_id": ${JSON.stringify(conversationId)},
    "participant_ids": ${JSON.stringify(participantIds)},
    "type": "dm", "created_at": ts, "last_message_at": ts, "updated_at": ts,
})
ptable = ddb.Table("Participants")
parts = ${JSON.stringify(participantIds)}
for uid in parts:
    ptable.put_item(Item={
        "user_id": uid, "conversation_id": ${JSON.stringify(conversationId)},
        "status": "active", "joined_at": ts,
        "role": "admin" if uid == parts[0] else "member",
        "muted_until": 0, "last_read_at": 0, "unread_count": 0, "left_at": 0,
        # The conversation-participants enrichment query reads the GSI1 index
        # (GSI1PK = conversation_id, GSI1SK = user_id). Without these the
        # participants list comes back empty, dmPartner never resolves, and the
        # call/recording UI (callsEnabled) stays disabled.
        "GSI1PK": ${JSON.stringify(conversationId)}, "GSI1SK": uid,
    })
print("ok")
`);
}

function seedReadyRecording(opts: {
  recordingId: string;
  callId: string;
  conversationId: string;
  participants: string[];
}): void {
  runPy(`
import boto3, time
from decimal import Decimal
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
ts = int(time.time())
ddb.Table("CallRecordings").put_item(Item={
    "recording_id": ${JSON.stringify(opts.recordingId)},
    "call_id": ${JSON.stringify(opts.callId)},
    "conversation_id": ${JSON.stringify(opts.conversationId)},
    "initiated_by": ${JSON.stringify(opts.participants[0])},
    "participants": ${JSON.stringify(opts.participants)},
    "status": "ready",
    "mime_type": "video/webm",
    "duration_seconds": Decimal("65"),
    "file_size_bytes": 2097152,
    "started_at": ts, "completed_at": ts,
    "created_at": ts, "updated_at": ts,
    "download_count": 0, "ttl": 0,
})
print("ok")
`);
}

function deleteRecording(recordingId: string): void {
  try {
    runPy(`
import boto3
ddb = boto3.resource("dynamodb", endpoint_url="http://localhost:8001",
                     region_name="us-east-1",
                     aws_access_key_id="test", aws_secret_access_key="test")
ddb.Table("CallRecordings").delete_item(Key={"recording_id": ${JSON.stringify(recordingId)}})
print("ok")
`);
  } catch {
    // ignore cleanup errors
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe("Section 146 — RecordingsPanel discoverability", () => {
  const convoWithRec = `conv_rec_${TS}`;
  const convoEmpty = `conv_rec_empty_${TS}`;
  const recId = `rec_${TS}`;

  test.beforeAll(() => {
    seedConversation(convoWithRec, [ALICE_ID, BOB_ID]);
    seedConversation(convoEmpty, [ALICE_ID, BOB_ID]);
    seedReadyRecording({
      recordingId: recId,
      callId: `call_${TS}`,
      conversationId: convoWithRec,
      participants: [ALICE_ID, BOB_ID],
    });
  });

  test.afterAll(() => {
    deleteRecording(recId);
  });

  test("146.1 menu exposes Recordings entry and panel lists a ready recording", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto(`/messages/${convoWithRec}`);

    // FAILS BEFORE FIX: the "Recordings" menu item did not exist.
    await page.getByRole("button", { name: "Conversation menu" }).click();
    const item = page.getByRole("menuitem", { name: "Recordings" });
    await expect(item).toBeVisible();
    await item.click();

    // PASSES AFTER FIX: panel renders the seeded ready recording with a download link.
    await expect(page.getByTestId("recording-item")).toBeVisible();
    await expect(page.getByRole("link", { name: "Download recording" })).toBeVisible();
  });

  test("146.2 panel shows empty state for a conversation with no recordings", async ({ page }) => {
    await injectAuth(page, "alice");
    await page.goto(`/messages/${convoEmpty}`);

    await page.getByRole("button", { name: "Conversation menu" }).click();
    await page.getByRole("menuitem", { name: "Recordings" }).click();

    await expect(page.getByTestId("recordings-empty")).toBeVisible();
  });
});
