/**
 * VIDEO SEGMENT 09 — Files & Integrations  (~90-120s)
 *
 * A guided tour of the platform's file + document tooling:
 *   - The File Manager (/files): a real folder/file tree with uploads
 *   - Full-text search: the Name / Content toggle pills + a live query result
 *   - Upload affordance in the toolbar
 *   - Google Drive integration: the "Connect Google Drive" button, the mock
 *     OAuth connect flow, and the connected Browse-Drive state
 *   - Document signing (/signing): the SignaturePacketComposer with the real
 *     react-pdf VIEWER (a rendered PDF page behind signature-field overlays) and
 *     the freehand SignatureDrawCanvas (the draw-your-signature pad)
 *
 * Pattern mirrors seg08-shop.demo.ts: ONE long test, paced with beat() and
 * narrated with caption()/titleCard(). Everything shown is brought on-screen and
 * PROVEN visible via reveal()'s toBeInViewport assertion.
 *
 * Cast (sessions seeded by e2e_admin_session_setup.py, loaded via loadSessions):
 *   - Alice — on camera. She owns the file manager (the demo uploads a few files
 *     to her tree) and is the SIGNER on the signature packet, so the signing page
 *     shows her the fill workflow with the freehand draw canvas.
 *   - Bob — off camera. He OWNS the signature packet (the composer only shows the
 *     signer fill panel + draw canvas to a NON-owner signer; an owner is the
 *     sender and only edits fields). Bob creates the packet, adds Alice as a
 *     signer with a drawn-signature field, and sends it.
 *
 * Seeding (all off-camera, before any UI is shown):
 *   - Files: a few small text files uploaded to Alice's file manager via the
 *     /v1/fs/upload API (one carries a unique token used for the live search).
 *   - Google Drive: reset + disconnect so the Files page starts disconnected;
 *     the connect beat drives the real mock OAuth flow (connect → callback).
 *   - Signing: a real one-page PDF is PUT into the in-process moto S3 at
 *     bucket=demo/key=contract.pdf so /mock/s3/demo/contract.pdf serves it (this
 *     is exactly the URL the composer builds from source_path "/demo/contract.pdf").
 *     A matching file_manager node is injected so Bob's packet create resolves the
 *     source. Bob adds Alice as a signer + a DRAWN signature field, sends the
 *     packet, and Alice pre-acknowledges the legal notice so the draw canvas
 *     renders immediately on camera. Alice's signing-mode preference is set to
 *     "drawn" via localStorage so the freehand pad is the default capture surface.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg09-files.demo.ts
 */
import { test, expect, type APIResponse } from "@playwright/test";
import { execSync } from "child_process";
import {
  BASE,
  API,
  injectAuth,
  caption,
  clearCaption,
  titleCard,
  beat,
  reveal,
  loadSessions,
  type SessionData,
} from "./_demo";

const PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";
const ALICE = "alice";
const BOB = "bob";

const SIGNATURE_MODE_PREF_KEY = "signature_packet_capture_mode_default";

/** Run a small inline python snippet against the local DDB (sources .env.local). */
function ddbPy(body: string): string {
  return execSync(
    `${PYTHON} -c "
import boto3, os, time
from pathlib import Path
env = Path('/home/ubuntu/testlogon/.env.local')
if env.exists():
    for line in env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
${body}
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 20_000 },
  ).toString();
}

/** Inject a file_manager node for a PDF so create_signature_packet can resolve it. */
function injectPdfNode(userSub: string, pdfPath: string): void {
  const name = pdfPath.split("/").pop()!;
  const parent = pdfPath.substring(0, pdfPath.lastIndexOf("/")) || "/";
  ddbPy(`
tbl = ddb.Table('file_manager')
tbl.put_item(Item={
    'PK': 'USER#${userSub}',
    'SK': 'NODE#${pdfPath}',
    'type': 'file',
    'path': '${pdfPath}',
    'name': '${name}',
    'name_lc': '${name.toLowerCase()}',
    'parent': '${parent}',
    'content_type': 'application/pdf',
    'size': 2048,
    'created_at': str(int(time.time())),
    'updated_at': str(int(time.time())),
    's3_key': 'demo/contract.pdf',
    's3_bucket': 'demo',
})
print('pdf node injected')
`);
}

/** A minimal but real one-page PDF with visible text (renders in react-pdf). */
function demoPdfBytes(): Buffer {
  const pdf =
    "%PDF-1.4\n" +
    "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
    "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n" +
    "3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 5 0 R>>>>/Contents 4 0 R>>endobj\n" +
    "4 0 obj<</Length 320>>stream\n" +
    "BT /F1 26 Tf 70 720 Td (MUTUAL NON-DISCLOSURE AGREEMENT) Tj ET\n" +
    "BT /F1 13 Tf 70 670 Td (This Agreement is made and entered into as of the date) Tj ET\n" +
    "BT /F1 13 Tf 70 650 Td (last signed below, by and between the parties identified) Tj ET\n" +
    "BT /F1 13 Tf 70 630 Td (in this document. Each party agrees to the terms herein.) Tj ET\n" +
    "BT /F1 13 Tf 70 200 Td (Signature:) Tj ET\n" +
    "BT /F1 13 Tf 70 170 Td (Date:) Tj ET\n" +
    "endstream endobj\n" +
    "5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n" +
    "trailer<</Size 6/Root 1 0 R>>\n" +
    "%%EOF";
  return Buffer.from(pdf, "latin1");
}

async function jsonOk(resp: APIResponse, what: string): Promise<any> {
  if (!resp.ok()) throw new Error(`${what} failed: ${resp.status()} ${await resp.text()}`);
  return resp.json();
}

test("Segment 09 — Files & Integrations", async ({ page, browser }) => {
  test.setTimeout(600_000);
  const sessions = loadSessions();
  const alice: SessionData = sessions[ALICE];
  const bob: SessionData = sessions[BOB];
  const stamp = Date.now();
  const searchToken = `demo${stamp}`;

  // ── Off-camera seeding ──────────────────────────────────────────────────────
  await injectAuth(page, ALICE);

  // 1. A few files into Alice's file manager (page.request carries Alice cookies).
  const files: Array<{ name: string; content: string }> = [
    { name: `Q4_Report.pdf`, content: "quarterly report contents" },
    { name: `Brand_Guidelines.pdf`, content: "brand guidelines contents" },
    { name: `${searchToken}_Invoice.txt`, content: "invoice line items and totals" },
    { name: `Meeting_Notes.txt`, content: "notes from the kickoff meeting" },
  ];
  for (const f of files) {
    const r = await page.request.post(`${API}/v1/fs/upload`, {
      params: { path: `/${f.name}` },
      multipart: { file: { name: f.name, mimeType: f.name.endsWith(".pdf") ? "application/pdf" : "text/plain", buffer: Buffer.from(f.content) } },
      headers: { "x-csrf-token": alice.csrf_token },
    });
    if (!r.ok() && r.status() !== 409) throw new Error(`upload ${f.name} failed: ${r.status()} ${await r.text()}`);
  }

  // 2. Google Drive: start disconnected so the connect beat is meaningful.
  await page.request.post(`${API}/mock/google-drive/reset`).catch(() => {});
  await page.request.post(`${API}/ui/integrations/google-drive/disconnect`, {
    headers: { "x-csrf-token": alice.csrf_token },
    data: {},
  }).catch(() => {});
  // Seed a couple of mock Drive files so the picker (once connected) has content.
  await page.request.post(`${API}/mock/google-drive/seed`, {
    data: {
      files: [
        { id: `gd_${stamp}_1`, name: `Contract_Draft.pdf`, mimeType: "application/pdf", size: "4096", parents: ["root"] },
        { id: `gd_${stamp}_2`, name: `Headshot.jpg`, mimeType: "image/jpeg", size: "8192", parents: ["root"] },
        { id: `gd_${stamp}_3`, name: `Shared_Folder`, mimeType: "application/vnd.google-apps.folder", parents: ["root"] },
      ],
    },
  }).catch(() => {});

  // 3. Signing: real PDF into moto S3 + matching file node + a sent packet where
  //    Alice is the signer with a drawn-signature field.
  const PDF_SOURCE_PATH = "/demo/contract.pdf"; // → /mock/s3/demo/contract.pdf
  await page.request.put(`${API}/mock/s3/demo`).catch(() => {}); // ensure bucket exists
  const putResp = await page.request.put(`${API}/mock/s3/demo/contract.pdf`, {
    headers: { "content-type": "application/pdf" },
    data: demoPdfBytes(),
  });
  if (!putResp.ok()) throw new Error(`PDF upload to mock S3 failed: ${putResp.status()}`);
  // Bob owns the packet (the composer only shows the draw canvas to a NON-owner signer).
  injectPdfNode(bob.user_sub, PDF_SOURCE_PATH);

  // Bob's API calls need Bob's cookies → drive them from a browser context that
  // carries his session (page.request would use Alice's cookies otherwise).
  const bobBrowserCtx = await browser.newContext();
  await bobBrowserCtx.addCookies(bob.cookies);
  const bobApiPage = await bobBrowserCtx.newPage();

  const bobPost = async (path: string, body: unknown) =>
    bobApiPage.request.post(`${API}${path}`, { headers: { "x-csrf-token": bob.csrf_token }, data: body });

  const created = await jsonOk(
    (await bobPost("/v1/signature-packets", { source_path: PDF_SOURCE_PATH, origin_channel: "share" })) as APIResponse,
    "create packet",
  );
  const packetId = created.packet_id as string;

  // Add Alice as a signer.
  await jsonOk(
    (await bobPost(`/v1/signature-packets/${packetId}/signers`, { signer_id: alice.user_sub, required: true })) as APIResponse,
    "add signer",
  );
  // Add a signature field assigned to Alice + a date field.
  await jsonOk(
    (await bobPost(`/v1/signature-packets/${packetId}/fields`, {
      action: "create",
      field_type: "signature",
      page: 1,
      x: 0.12,
      y: 0.72,
      width: 0.28,
      height: 0.08,
      assigned_signer_id: alice.user_sub,
      required: true,
    })) as APIResponse,
    "add signature field",
  );
  await jsonOk(
    (await bobPost(`/v1/signature-packets/${packetId}/fields`, {
      action: "create",
      field_type: "date",
      page: 1,
      x: 0.12,
      y: 0.82,
      width: 0.2,
      height: 0.05,
      assigned_signer_id: alice.user_sub,
      required: false,
    })) as APIResponse,
    "add date field",
  );
  // Send the packet → Alice becomes an active signer.
  await jsonOk((await bobPost(`/v1/signature-packets/${packetId}/send`, {})) as APIResponse, "send packet");

  // Alice pre-acknowledges the legal notice so the fill panel + draw canvas render
  // immediately (otherwise can_fill_fields is gated behind the acknowledge button).
  await page.request.post(`${API}/v1/signature-packets/${packetId}/acknowledge-legal-notice`, {
    headers: { "x-csrf-token": alice.csrf_token },
    data: {},
  }).catch(() => {});

  await bobBrowserCtx.close();

  // Make "drawn" the default signature capture mode for Alice so the freehand pad
  // is the surface shown (instead of the typed text input).
  await page.addInitScript(
    ({ key, mode }: { key: string; mode: string }) => localStorage.setItem(key, mode),
    { key: SIGNATURE_MODE_PREF_KEY, mode: "drawn" },
  );

  // ── Load the shell ──────────────────────────────────────────────────────────
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1000);

  // ── 1. Intro ────────────────────────────────────────────────────────────────
  await titleCard(page, 9, "Files & Integrations", "File manager · search · Google Drive · PDF signing");

  // ── 2. File manager ─────────────────────────────────────────────────────────
  await page.goto(`${BASE}/files`, { waitUntil: "domcontentloaded" });
  await expect(page.locator("input[placeholder*='Search by name']")).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1400);

  await reveal(
    page,
    page.getByRole("heading", { name: /^Files$/ }).first(),
    "The File Manager",
    "A full cloud drive built in — folders, uploads, and rich previews",
    { ms: 3800 },
  );
  await reveal(
    page,
    page.getByText("Q4_Report.pdf").first(),
    "Your files",
    "Every file lives in a familiar tree, with type, size, and date",
    { ms: 4200 },
  );

  // ── 3. Search: Name / Content toggle + live result ──────────────────────────
  await reveal(
    page,
    page.locator("button.rounded-full").filter({ hasText: /^Name$/ }),
    "Name vs. content search",
    "Search by file name, or flip the toggle to search inside file contents",
    { ms: 4000 },
  );
  await reveal(
    page,
    page.locator("input[placeholder*='Search by name']"),
    "Live full-text search",
    "Results filter as you type, instantly",
    { ms: 2600 },
  );
  // Run the search.
  const searchResp = page.waitForResponse(
    (r) => r.url().includes("/v1/fs/search") && !r.url().includes("search-text") && r.request().method() === "GET",
  );
  await page.locator("input[placeholder*='Search by name']").fill(searchToken);
  await searchResp.catch(() => {});
  await page.waitForTimeout(1200);
  await reveal(
    page,
    page.getByText(`${searchToken}_Invoice.txt`).first(),
    "Matched in milliseconds",
    `One match for "${searchToken}"`,
    { ms: 4200 },
  );
  // Clear the search to restore the listing.
  await page.locator("input[placeholder*='Search by name']").clear();
  await page.waitForTimeout(1000);

  // ── 4. Upload affordance ────────────────────────────────────────────────────
  const uploadBtn = page.getByRole("button", { name: /upload/i }).first();
  await reveal(
    page,
    uploadBtn,
    "Drag-and-drop uploads",
    "Upload new files — or drop them straight onto the page",
    { ms: 3800 },
  );

  // ── 5. Google Drive integration ─────────────────────────────────────────────
  await reveal(
    page,
    page.getByTestId("connect-google-drive-button"),
    "Connect Google Drive",
    "Link your Google Drive to browse and import files",
    { ms: 4000 },
  );
  await reveal(
    page,
    page.getByTestId("google-drive-disconnected-badge"),
    "Not connected — yet",
    "The integration starts disconnected and stays read-only until you opt in",
    { ms: 3400 },
  );

  // Drive the mock OAuth connect flow off-camera, then reload to show connected.
  const connectBody = await jsonOk(
    (await page.request.get(`${API}/ui/integrations/google-drive/connect`)) as APIResponse,
    "drive connect",
  );
  const authUrl = new URL(connectBody.auth_url, API);
  const code = authUrl.searchParams.get("code") || "";
  const state = authUrl.searchParams.get("state") || "";
  await jsonOk(
    (await page.request.post(`${API}/ui/integrations/google-drive/callback`, {
      headers: { "x-csrf-token": alice.csrf_token, "content-type": "application/json" },
      data: { code, state, redirect_uri: "" },
    })) as APIResponse,
    "drive callback",
  );

  await caption(page, "Secure OAuth handshake", "A one-tap consent flow connects your account");
  await beat(page, 2600);

  await page.goto(`${BASE}/files`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("google-drive-connected-badge")).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1200);
  await reveal(
    page,
    page.getByTestId("google-drive-connected-badge"),
    "Google Drive connected",
    "Now you can browse and import Drive files directly",
    { ms: 4000 },
  );

  // Open the Drive picker dialog.
  await page.getByTestId("google-drive-browse-button").click().catch(() => {});
  await expect(page.locator('[data-testid="drive-picker-dialog"]')).toBeVisible({ timeout: 8000 });
  await page.waitForTimeout(1000);
  await reveal(
    page,
    page.locator('[data-testid="drive-picker-dialog"]'),
    "Browse your Drive",
    "A built-in picker lists your Drive files and folders to import",
    { ms: 4500 },
  );
  await page.getByRole("button", { name: "Cancel" }).click().catch(() => {});
  await page.waitForTimeout(600);

  // ── 6. PDF signing ──────────────────────────────────────────────────────────
  await caption(page, "Document signing", "Loading the signature workspace…");
  await page.goto(`${BASE}/signing`, { waitUntil: "domcontentloaded" });
  await expect(page.getByText("Document Signing").first()).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(1000);

  // Load the seeded packet (Alice is the signer).
  await page.getByPlaceholder("Packet ID").fill(packetId);
  await page.getByRole("button", { name: /^Load$/ }).click().catch(() => {});
  // Wait for the packet to load + the PDF page to render.
  await expect(page.getByTestId("signature-canvas")).toBeVisible({ timeout: 12_000 });
  // react-pdf renders an actual <canvas> inside the page wrapper once the PDF loads.
  await expect(page.locator('[data-testid="signature-canvas"] canvas').first()).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1500);

  await reveal(
    page,
    page.getByText("Document Signing").first(),
    "Send documents for signature",
    "Compose a packet from any PDF, place fields, and route it to signers",
    { ms: 3600 },
  );
  await reveal(
    page,
    page.locator('[data-testid="signature-canvas"] canvas').first(),
    "The PDF, rendered live",
    "The real document renders in-browser with the signature fields overlaid",
    { ms: 4800 },
  );

  // Reveal the freehand draw pad (signer fill panel, drawn mode).
  await reveal(
    page,
    page.getByTestId("signer-fill-panel"),
    "Sign as the recipient",
    "Assigned signers get a guided fill workflow right in the browser",
    { ms: 3600 },
  );
  const drawPad = page.locator('[data-testid^="field-drawn-"]').first();
  await reveal(
    page,
    drawPad,
    "Draw your signature",
    "A freehand pad captures a real, hand-drawn signature",
    { ms: 4000 },
  );
  // Draw a quick signature stroke on the pad for the camera.
  const box = await drawPad.boundingBox();
  if (box) {
    const cy = box.y + box.height / 2;
    await page.mouse.move(box.x + box.width * 0.12, cy + 12);
    await page.mouse.down();
    await page.mouse.move(box.x + box.width * 0.3, cy - 20, { steps: 8 });
    await page.mouse.move(box.x + box.width * 0.5, cy + 18, { steps: 8 });
    await page.mouse.move(box.x + box.width * 0.7, cy - 16, { steps: 8 });
    await page.mouse.move(box.x + box.width * 0.88, cy + 8, { steps: 8 });
    await page.mouse.up();
    await page.waitForTimeout(1400);
  }
  await reveal(
    page,
    drawPad,
    "Signature captured",
    "Typed or drawn — the platform records a tamper-evident audit trail",
    { ms: 4000 },
  );

  // ── 7. Outro ────────────────────────────────────────────────────────────────
  await caption(page, "Files & Integrations ✓", "Next: Calendar & Booking");
  await beat(page, 3200);
  await clearCaption(page);
  await beat(page, 900);
});
