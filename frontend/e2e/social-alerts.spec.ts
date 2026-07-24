/**
 * E2E tests for SOC-004: Notification System Expansion
 *
 * Section 110: Social Alert Unread Count & Mark-Read API (5 tests)
 * Section 111: Per-Type Notification Preferences API (4 tests)
 * Section 112: Social Alert Emission (4 tests)
 *
 * Auth: cookie-based sessions via e2e_admin_session_setup.py.
 * Seeds alert items directly into DynamoDB for deterministic assertions.
 */

import { test, expect, type Page, type Browser } from "@playwright/test";
import { execSync } from "child_process";
import * as path from "path";
import { API } from "./cpp.config";
import { loadSessions } from "./helpers/session";
const REPO_ROOT = process.env.E2E_REPO_ROOT || path.resolve(process.cwd(), "..");

// ─── Constants ────────────────────────────────────────────────────────────────

const PYTHON = REPO_ROOT + "/.venv/bin/python3";
const ALICE_SUB = "e2e_alice@test.local";
// Session keys used in e2e_admin_session_setup.py
const ALICE_KEY = "alice";
const ROOT_KEY = "root";
const TS = Date.now();

// ─── Session bootstrap ────────────────────────────────────────────────────────

interface AdminSessionData {
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

let _adminSessions: Record<string, AdminSessionData> | null = null;
function getAdminSessions(): Record<string, AdminSessionData> {
  if (!_adminSessions) {
    _adminSessions = loadSessions();
  }
  return _adminSessions!;
}

async function newIdentityPage(
  browser: Browser,
  identity: string,
): Promise<Page> {
  const sessions = getAdminSessions();
  const page = await browser.newPage();
  await page.context().addCookies(sessions[identity].cookies);
  return page;
}

// ─── Request helpers ──────────────────────────────────────────────────────────

async function apiPost(
  page: Page,
  sessionKey: string,
  path: string,
  body?: unknown,
) {
  const sess = getAdminSessions()[sessionKey];
  return page.request.post(`${API}${path}`, {
    data: body ?? {},
    headers: {
      "x-csrf-token": sess.csrf_token,
      "Content-Type": "application/json",
    },
  });
}

async function apiGet(page: Page, path: string, params?: Record<string, string>) {
  return page.request.get(`${API}${path}`, { params });
}

// ─── DDB seed helpers ─────────────────────────────────────────────────────────

/**
 * Clear all unread alerts for a user to establish a known baseline.
 */
function clearUnreadAlerts(userSub: string): void {
  execSync(
    `${PYTHON} -c "
import boto3, os
from pathlib import Path

env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('alerts')
resp = tbl.query(
    KeyConditionExpression=boto3.dynamodb.conditions.Key('user_sub').eq('${userSub}'),
    ProjectionExpression='user_sub, alert_id, #r',
    ExpressionAttributeNames={'#r': 'read'},
)
for item in resp.get('Items', []):
    if not item.get('read', True):
        tbl.update_item(
            Key={'user_sub': item['user_sub'], 'alert_id': item['alert_id']},
            UpdateExpression='SET #r = :t, read_at = :now',
            ExpressionAttributeNames={'#r': 'read'},
            ExpressionAttributeValues={':t': True, ':now': 0},
        )
# Reset the UNREAD_COUNT sentinel
tbl.put_item(Item={'user_sub': '${userSub}', 'alert_id': 'UNREAD_COUNT', 'count': 0, 'updated_at': 0})
print('cleared')
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
}

/**
 * Seed N individual unread alerts for a user.
 * Returns the list of alert_ids seeded.
 */
function seedUnreadAlerts(userSub: string, count: number, prefix: string): string[] {
  const result = execSync(
    `${PYTHON} -c "
import boto3, os, uuid, time, json
from pathlib import Path

env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('alerts')
ids = []
ts = int(time.time())
for i in range(${count}):
    alert_id = f'{ts + i:010d}#{uuid.uuid4().hex}'
    tbl.put_item(Item={
        'user_sub': '${userSub}',
        'alert_id': alert_id,
        'ts': ts + i,
        'event': 'new_follower',
        'outcome': 'success',
        'title': '${prefix} alert ' + str(i),
        'read': False,
        'read_at': 0,
        'details': {'source': '${prefix}'},
    })
    ids.append(alert_id)
# Increment the UNREAD_COUNT sentinel
tbl.update_item(
    Key={'user_sub': '${userSub}', 'alert_id': 'UNREAD_COUNT'},
    UpdateExpression='SET #c = if_not_exists(#c, :zero) + :delta, updated_at = :now',
    ExpressionAttributeNames={'#c': 'count'},
    ExpressionAttributeValues={':delta': ${count}, ':zero': 0, ':now': ts},
)
print(json.dumps(ids))
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  ).toString().trim();
  return JSON.parse(result);
}

/**
 * Seed a BATCH alert for a user.
 */
function seedBatchAlert(
  userSub: string,
  batchKey: string,
  alertType: string,
  actorCount: number,
): void {
  execSync(
    `${PYTHON} -c "
import boto3, os, time
from pathlib import Path

env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('alerts')
ts = str(int(time.time()))
actors = []
for i in range(${actorCount}):
    actors.append({'user_id': f'actor_{i}', 'display_name': f'Actor {i}', 'timestamp': ts})
tbl.put_item(Item={
    'user_sub': '${userSub}',
    'alert_id': 'BATCH#${batchKey}',
    'alert_type': '${alertType}',
    'batch_key': '${batchKey}',
    'actors': actors,
    'actor_count': ${actorCount},
    'title': f'Actor {${actorCount} - 1} and {${actorCount} - 1} others reacted to your post',
    'read': False,
    'created_at': ts,
    'updated_at': ts,
    'details': {'post_id': 'test_post_${TS}'},
})
# Increment the UNREAD_COUNT sentinel
from boto3.dynamodb.conditions import Key as K
tbl.update_item(
    Key={'user_sub': '${userSub}', 'alert_id': 'UNREAD_COUNT'},
    UpdateExpression='SET #c = if_not_exists(#c, :zero) + :one, updated_at = :now',
    ExpressionAttributeNames={'#c': 'count'},
    ExpressionAttributeValues={':one': 1, ':zero': 0, ':now': int(time.time())},
)
print('seeded')
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
}

/**
 * Delete a specific alert by pk/sk.
 */
function deleteAlert(userSub: string, alertId: string): void {
  execSync(
    `${PYTHON} -c "
import boto3, os
from pathlib import Path

env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('alerts')
tbl.delete_item(Key={'user_sub': '${userSub}', 'alert_id': '${alertId}'})
print('deleted')
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
}

/**
 * Get the raw DDB item for a batch alert.
 */
function getBatchAlert(userSub: string, batchKey: string): Record<string, unknown> | null {
  const result = execSync(
    `${PYTHON} -c "
import boto3, os, json
from decimal import Decimal
from pathlib import Path

env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return int(o) if o == int(o) else float(o)
        return super().default(o)

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('alerts')
resp = tbl.get_item(Key={'user_sub': '${userSub}', 'alert_id': 'BATCH#${batchKey}'})
item = resp.get('Item')
if item:
    print(json.dumps(item, cls=DecimalEncoder))
else:
    print('null')
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  ).toString().trim();
  if (result === "null") return null;
  return JSON.parse(result);
}

/**
 * Reset type_preferences on the alert_prefs table for a user.
 */
function resetTypePreferences(userSub: string): void {
  execSync(
    `${PYTHON} -c "
import boto3, os
from pathlib import Path

env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('alert_prefs')
try:
    tbl.update_item(
        Key={'user_sub': '${userSub}'},
        UpdateExpression='REMOVE type_preferences',
    )
except Exception:
    pass
print('reset')
"`,
    { cwd: REPO_ROOT, timeout: 15_000 },
  );
}

// =============================================================================
// Test setup
// =============================================================================

let alicePage: Page;

test.beforeAll(async ({ browser }) => {
  // Ensure clean baseline
  clearUnreadAlerts(ALICE_SUB);
  resetTypePreferences(ALICE_SUB);

  // Create page with auth cookies
  alicePage = await newIdentityPage(browser, ALICE_KEY);
});

test.afterAll(async () => {
  await alicePage?.close();
});

// =============================================================================
// Section 110: Social Alert Unread Count & Mark-Read API
// =============================================================================

test.describe("110 · Social Alert Unread Count & Mark-Read API", () => {
  test("110.1 Get unread count for Alice (baseline >= 0)", async () => {
    const resp = await apiGet(alicePage, "/ui/alerts/unread-count");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(typeof data.unread_count).toBe("number");
    expect(data.unread_count).toBeGreaterThanOrEqual(0);
  });

  test("110.2 Seed 3 unread alerts, verify unread count >= 3", async () => {
    // Clear existing unread to get a clean baseline
    clearUnreadAlerts(ALICE_SUB);

    // Verify baseline is 0
    const baseResp = await apiGet(alicePage, "/ui/alerts/unread-count");
    const baseData = await baseResp.json();
    expect(baseData.unread_count).toBe(0);

    // Seed 3 unread alerts
    seedUnreadAlerts(ALICE_SUB, 3, `s110_${TS}`);

    const resp = await apiGet(alicePage, "/ui/alerts/unread-count");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.unread_count).toBeGreaterThanOrEqual(3);
  });

  test("110.3 Mark all read, then verify count is 0", async () => {
    const markResp = await apiPost(alicePage, ALICE_KEY, "/ui/alerts/mark-all-read");
    expect(markResp.status()).toBe(200);
    const markData = await markResp.json();
    expect(markData.marked_count).toBeGreaterThanOrEqual(3);

    const countResp = await apiGet(alicePage, "/ui/alerts/unread-count");
    const countData = await countResp.json();
    expect(countData.unread_count).toBe(0);
  });

  test("110.4 Seed a BATCH alert, verify it shows in unread count", async () => {
    // Clear all first
    clearUnreadAlerts(ALICE_SUB);

    const batchKey = `batch_test_${TS}`;
    seedBatchAlert(ALICE_SUB, batchKey, "post_reaction", 3);

    const resp = await apiGet(alicePage, "/ui/alerts/unread-count");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.unread_count).toBeGreaterThanOrEqual(1);

    // Clean up
    deleteAlert(ALICE_SUB, `BATCH#${batchKey}`);
  });

  test("110.5 Mark all read again, verify batch alert also marked", async () => {
    // Seed a fresh batch alert
    const batchKey = `batch_mark_${TS}`;
    seedBatchAlert(ALICE_SUB, batchKey, "post_liked", 2);

    // Also seed a regular unread alert
    seedUnreadAlerts(ALICE_SUB, 1, `s110_5_${TS}`);

    // Verify at least 2 unread (batch + regular)
    const preResp = await apiGet(alicePage, "/ui/alerts/unread-count");
    const preData = await preResp.json();
    expect(preData.unread_count).toBeGreaterThanOrEqual(2);

    // Mark all read
    const markResp = await apiPost(alicePage, ALICE_KEY, "/ui/alerts/mark-all-read");
    expect(markResp.status()).toBe(200);
    const markData = await markResp.json();
    expect(markData.marked_count).toBeGreaterThanOrEqual(2);

    // Verify count is 0
    const postResp = await apiGet(alicePage, "/ui/alerts/unread-count");
    const postData = await postResp.json();
    expect(postData.unread_count).toBe(0);

    // Verify the batch alert itself is now read
    const batchItem = getBatchAlert(ALICE_SUB, batchKey);
    expect(batchItem).not.toBeNull();
    expect(batchItem!.read).toBe(true);
  });
});

// =============================================================================
// Section 111: Per-Type Notification Preferences API
// =============================================================================

test.describe("111 · Per-Type Notification Preferences API", () => {
  test("111.1 Get type preferences returns a map with known social types", async () => {
    const resp = await apiGet(alicePage, "/ui/alerts/type-preferences");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.type_preferences).toBeTruthy();

    // Should contain known social alert types
    const prefs = data.type_preferences;
    const socialTypes = [
      "new_follower",
      "post_liked",
      "post_reaction",
      "post_comment",
      "comment_reply",
      "mention",
      "subscription_started",
      "post_shared",
      "post_tip",
      "message_tip",
    ];
    for (const st of socialTypes) {
      expect(prefs[st]).toBeTruthy();
      expect(typeof prefs[st].enabled).toBe("boolean");
      expect(typeof prefs[st].email).toBe("boolean");
      expect(typeof prefs[st].push).toBe("boolean");
      expect(typeof prefs[st].in_app).toBe("boolean");
      expect(typeof prefs[st].sms).toBe("boolean");
    }
  });

  test("111.2 Disable post_reaction type", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/alerts/type-preferences", {
      alert_type: "post_reaction",
      enabled: false,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.alert_type).toBe("post_reaction");
    expect(data.enabled).toBe(false);
  });

  test("111.3 Re-get preferences verifies post_reaction.enabled is false", async () => {
    const resp = await apiGet(alicePage, "/ui/alerts/type-preferences");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.type_preferences.post_reaction.enabled).toBe(false);
    // Other fields should still have defaults
    expect(data.type_preferences.post_reaction.email).toBe(true);
    expect(data.type_preferences.post_reaction.push).toBe(true);
    expect(data.type_preferences.post_reaction.in_app).toBe(true);
    expect(data.type_preferences.post_reaction.sms).toBe(false);
  });

  test("111.4 Re-enable post_reaction and update channel settings", async () => {
    const resp = await apiPost(alicePage, ALICE_KEY, "/ui/alerts/type-preferences", {
      alert_type: "post_reaction",
      enabled: true,
      sms: true,
      email: false,
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.alert_type).toBe("post_reaction");
    expect(data.enabled).toBe(true);
    expect(data.sms).toBe(true);
    expect(data.email).toBe(false);

    // Verify via GET
    const getResp = await apiGet(alicePage, "/ui/alerts/type-preferences");
    const getData = await getResp.json();
    expect(getData.type_preferences.post_reaction.enabled).toBe(true);
    expect(getData.type_preferences.post_reaction.sms).toBe(true);
    expect(getData.type_preferences.post_reaction.email).toBe(false);

    // Clean up: reset to defaults
    resetTypePreferences(ALICE_SUB);
  });
});

// =============================================================================
// Section 112: Social Alert Emission
// =============================================================================

test.describe("112 · Social Alert Emission", () => {
  test("112.1 Seed a social alert (new_follower), verify it appears in alerts list", async () => {
    const uniqueTitle = `Follower alert ${TS}`;
    // Seed directly via DDB (simulating what emit_social_alert + write_alert does)
    execSync(
      `${PYTHON} -c "
import boto3, os, uuid, time
from pathlib import Path

env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tbl = ddb.Table('alerts')
ts = int(time.time())
alert_id = f'{ts:010d}#{uuid.uuid4().hex}'
tbl.put_item(Item={
    'user_sub': '${ALICE_SUB}',
    'alert_id': alert_id,
    'ts': ts,
    'event': 'new_follower',
    'outcome': 'success',
    'title': '${uniqueTitle}',
    'read': False,
    'read_at': 0,
    'details': {'actor': 'bob_user', 'source': 'e2e_test'},
})
print(alert_id)
"`,
      { cwd: REPO_ROOT, timeout: 15_000 },
    );

    // Verify it appears in the alerts list
    const resp = await apiGet(alicePage, "/ui/alerts", { limit: "50" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.alerts.some(
      (a: { title: string; event: string }) =>
        a.title === uniqueTitle && a.event === "new_follower",
    );
    expect(found).toBe(true);
  });

  test("112.2 Seed 3 actors into same batch_key, verify actor_count >= 3", async () => {
    const batchKey = `emission_batch_${TS}`;

    // Seed batch alert with 3 actors directly
    seedBatchAlert(ALICE_SUB, batchKey, "post_reaction", 3);

    // Verify the batch alert in DDB has actor_count >= 3
    const batchItem = getBatchAlert(ALICE_SUB, batchKey);
    expect(batchItem).not.toBeNull();
    expect(Number(batchItem!.actor_count)).toBeGreaterThanOrEqual(3);
    expect(Array.isArray(batchItem!.actors)).toBe(true);
    expect((batchItem!.actors as unknown[]).length).toBeGreaterThanOrEqual(3);

    // Verify it appears in the alerts list (unread)
    const resp = await apiGet(alicePage, "/ui/alerts", { unread_only: "1" });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    const found = data.alerts.some(
      (a: { alert_id: string }) => a.alert_id === `BATCH#${batchKey}`,
    );
    expect(found).toBe(true);

    // Clean up
    deleteAlert(ALICE_SUB, `BATCH#${batchKey}`);
  });

  test("112.3 Self-notification suppression: emit_social_alert returns None when recipient==actor", async () => {
    // Call emit_social_alert directly via Python where recipient == actor
    const result = execSync(
      `${PYTHON} -c "
import sys, os
sys.path.insert(0, '${REPO_ROOT}')
from pathlib import Path

env = Path('${REPO_ROOT}/.env.local')
for line in env.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())

from app.core.tables import T
from app.services.social_alerts import emit_social_alert

result = emit_social_alert(
    recipient_user_id='${ALICE_SUB}',
    alert_type='new_follower',
    actor_user_id='${ALICE_SUB}',
    actor_display_name='Alice',
    title='Alice followed you',
    details={'source': 'self_test_${TS}'},
)
print('None' if result is None else 'emitted')
"`,
      { cwd: REPO_ROOT, timeout: 15_000 },
    ).toString().trim();
    expect(result).toBe("None");
  });

  test("112.4 Alert types list includes social types", async () => {
    const resp = await apiGet(alicePage, "/ui/alerts/types");
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(Array.isArray(data.types)).toBe(true);
    expect(Array.isArray(data.event_types)).toBe(true);

    // Verify known social types are present
    const socialTypes = [
      "new_follower",
      "post_liked",
      "post_reaction",
      "post_comment",
      "comment_reply",
      "mention",
      "subscription_started",
      "post_shared",
      "post_tip",
      "message_tip",
    ];
    for (const st of socialTypes) {
      expect(data.types).toContain(st);
      expect(data.event_types).toContain(st);
    }
  });
});
