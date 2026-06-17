/**
 * Section 103: Moderation Reports — create, dedup, validation
 *
 * Auth: Cookie sessions via e2e_admin_session_setup.py
 * Identities: alice (USER)
 */
import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

const BASE = "http://localhost:3000";
const TS = Date.now();

interface SessionData {
  user_sub: string;
  session_id: string;
  csrf_token: string;
  access_token: string;
  cookies: Array<{
    name: string; value: string; domain: string; path: string;
    httpOnly: boolean; secure: boolean; sameSite: "Lax" | "Strict" | "None"; expires: number;
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

async function newPage(browser: Browser, identity: string): Promise<Page> {
  const page = await browser.newPage();
  await page.context().addCookies(getSessions()[identity].cookies);
  return page;
}

async function apiPost(page: Page, id: string, path: string, body?: unknown) {
  const s = getSessions()[id];
  return page.request.post(`${BASE}${path}`, {
    data: body ?? {},
    headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
  });
}

function seedFeedPost(userSub: string, postId: string): void {
  execSync(
    `.venv/bin/python3 -c "import boto3; ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test'); tbl = ddb.Table('app_single_table'); tbl.put_item(Item={'pk': 'POST#${postId}', 'sk': 'META', 'post_id': '${postId}', 'author_id': '${userSub}', 'text': 'Test post', 'image_urls': ['https://example.com/img1.jpg'], 'created_at': 1700000000, 'status': 'published'})"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  );
}

function seedMessage(conversationId: string, messageId: string): void {
  execSync(
    `.venv/bin/python3 -c "import boto3; ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test'); tbl = ddb.Table('Messages'); tbl.put_item(Item={'conversation_id': '${conversationId}', 'message_id': '${messageId}', 'text': 'Test message', 'sender_id': 'someone', 'created_at': 1700000000})"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  );
}

function seedTopicRows(): void {
  const topics = ["sexual", "extortion", "criminal", "spam", "racist"];
  const items = topics.map(t => `{'report_id': 'TOPIC#${t}', 'entity_type': 'topic_seed'}`).join(", ");
  execSync(
    `.venv/bin/python3 -c "import boto3; ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8001', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test'); from app.core.settings import S; tbl = ddb.Table(S.content_reports_table_name); [tbl.put_item(Item=i) for i in [${items}]]"`,
    { cwd: REPO_ROOT, timeout: 10_000 },
  );
}

const POST_ID = `mod_post_${TS}`;
const CONVO_ID = `mod_convo_${TS}`;
const MSG_ID = `mod_msg_${TS}`;

// ─── 103. Moderation Reports ─────────────────────────────────────────────

test.describe.serial("103 — Moderation Reports: create, dedup, validation", () => {
  let alicePage: Page;
  let firstReportId: string;

  test.beforeAll(async ({ browser }) => {
    alicePage = await newPage(browser, "alice");
    seedTopicRows();
    seedFeedPost(getSessions()["alice"].user_sub, POST_ID);
    seedMessage(CONVO_ID, MSG_ID);
  });

  test.afterAll(async () => {
    await alicePage?.close();
  });

  test("103.1 Create moderation report for feed post", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/moderation/reports", {
      content_type: "feed_post",
      content_id: POST_ID,
      topics: ["spam"],
      reason_text: "This post looks like spam content that should be reviewed",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.report_id).toBeTruthy();
    expect(data.ticket_id).toBeTruthy();
    expect(data.status).toBe("submitted");
    expect(data.created_at).toBeGreaterThan(0);
    firstReportId = data.report_id;
  });

  test("103.2 Duplicate report within idempotency window returns deduplicated", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/moderation/reports", {
      content_type: "feed_post",
      content_id: POST_ID,
      topics: ["spam"],
      reason_text: "This is a duplicate report for the same content within window",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("deduplicated");
    expect(data.report_id).toBe(firstReportId);
  });

  test("103.3 Report with multiple valid topics", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/moderation/reports", {
      content_type: "message",
      content_id: MSG_ID,
      conversation_id: CONVO_ID,
      topics: ["sexual", "extortion"],
      reason_text: "This message contains concerning content that violates terms",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
    expect(data.status).toBe("submitted");
  });

  test("103.4 Report feed_media with media_index", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/moderation/reports", {
      content_type: "feed_media",
      content_id: POST_ID,
      post_id: POST_ID,
      media_index: 0,
      topics: ["criminal"],
      reason_text: "This image violates community guidelines and should be removed",
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
  });

  test("103.5 Invalid topic returns 422", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/moderation/reports", {
      content_type: "feed_post",
      content_id: POST_ID,
      topics: ["nonexistent_topic"],
      reason_text: "This should fail because the topic is invalid per validation",
    });
    expect(resp.status()).toBe(422);
  });

  test("103.6 Reason text too short returns 422", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/moderation/reports", {
      content_type: "feed_post",
      content_id: POST_ID,
      topics: ["spam"],
      reason_text: "hi",
    });
    expect(resp.status()).toBe(422);
  });

  test("103.7 Non-existent content returns 404", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/moderation/reports", {
      content_type: "feed_post",
      content_id: `nonexistent_${TS}`,
      topics: ["spam"],
      reason_text: "This post does not exist and should return 404 from validation",
    });
    expect(resp.status()).toBe(404);
  });

  test("103.8 Message report without conversation_id returns 400", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/moderation/reports", {
      content_type: "message",
      content_id: MSG_ID,
      topics: ["spam"],
      reason_text: "Missing conversation_id should return bad request error here",
    });
    expect(resp.status()).toBe(400);
  });

  test("103.9 Feed comment without post_id returns 400", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/moderation/reports", {
      content_type: "feed_comment",
      content_id: `comment_${TS}`,
      topics: ["spam"],
      reason_text: "Missing post_id for feed_comment should return bad request error",
    });
    expect(resp.status()).toBe(400);
  });

  test("103.10 Backward-compatible /moderation/reports endpoint works", async () => {
    const s = getSessions()["alice"];
    const resp = await alicePage.request.post("http://localhost:8000/moderation/reports", {
      data: {
        content_type: "feed_post",
        content_id: POST_ID,
        topics: ["racist"],
        reason_text: "Testing backward-compatible endpoint path for moderation reports",
      },
      headers: { "x-csrf-token": s.csrf_token, "Content-Type": "application/json" },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.ok).toBe(true);
  });

  test("103.11 Empty topics list returns 422", async () => {
    const resp = await apiPost(alicePage, "alice", "/v1/moderation/reports", {
      content_type: "feed_post",
      content_id: POST_ID,
      topics: [],
      reason_text: "Empty topics should fail pydantic validation constraints here",
    });
    expect(resp.status()).toBe(422);
  });
});
