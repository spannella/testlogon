/**
 * VIDEO SEGMENT 19 — Accounting & Taxes  (~1.5 min)
 *
 * The money paperwork a real platform has to produce:
 *   - Consumer tax documents — an annual, categorized spending summary + PDF
 *   - 1099-NEC creator earnings forms (auto-generated past the $600 threshold)
 *   - Itemized invoices for every transaction, with downloadable PDFs
 *
 * Seeding (off camera, all truthful):
 *   - DDB billing ledger: DEBIT rows dated 2026 (consumer spending → tax docs,
 *     which default to the current year) and CREDIT rows dated 2025 totalling
 *     $700 (creator earnings → the 1099-NEC for the prior tax year).
 *   - DDB invoices: three itemized invoice rows.
 *   - APIs (cookie + CSRF as Alice): submit a W-9, generate the 2025 1099-NEC,
 *     and generate the 2026 consumer tax document — exactly the production paths.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg19-accounting.demo.ts
 */
import { test } from "@playwright/test";
import { BASE, injectAuth, caption, clearCaption, titleCard, beat, reveal, api, py, loadSessions } from "./_demo";

test("Segment 19 — Accounting & Taxes", async ({ page }) => {
  test.setTimeout(600_000);
  const aliceSub = loadSessions()["alice"].user_sub;

  // ── Seed ledger (2026 spending + 2025 earnings) + invoices ────────────────
  py(`
import uuid, datetime
import boto3.dynamodb.conditions as C

def ts_at(y, m, d):
    return int(datetime.datetime(y, m, d, 12, 0, 0, tzinfo=datetime.timezone.utc).timestamp())

bill = ddb.Table('billing')
pk = 'USER#${aliceSub}'

# Idempotent: clear prior seg19 ledger seed rows.
resp = bill.query(KeyConditionExpression=C.Key('pk').eq(pk) & C.Key('sk').begins_with('LEDGER#'))
for it in resp.get('Items', []):
    if (it.get('meta') or {}).get('content_id') == 'seg19_seed':
        bill.delete_item(Key={'pk': pk, 'sk': it['sk']})

def put_ledger(ts, kind, cents, reason, ctype):
    eid = uuid.uuid4().hex
    bill.put_item(Item={
        'pk': pk, 'sk': 'LEDGER#' + str(ts) + '#' + eid, 'entry_id': eid, 'ts': ts,
        'type': kind, 'amount_cents': cents, 'currency': 'USD', 'state': 'settled',
        'reason': reason,
        'ledger_date': datetime.datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d'),
        'meta': {'content_type': ctype, 'content_id': 'seg19_seed'},
    })

d26 = ts_at(2026, 3, 15)
put_ledger(d26 + 1, 'debit', 4999, 'Subscription: Gold plan', 'subscription')
put_ledger(d26 + 2, 'debit', 1500, 'Tip sent to a creator', 'message')
put_ledger(d26 + 3, 'debit', 8900, 'Purchase: shop order', 'order')
put_ledger(d26 + 4, 'debit', 999,  'Unlock: locked post', 'post')
put_ledger(d26 + 5, 'debit', 5000, 'Deposit: wallet top-up', 'deposit')

d25 = ts_at(2025, 6, 1)
put_ledger(d25 + 1, 'credit', 40000, 'Tip: message', 'message')
put_ledger(d25 + 2, 'credit', 30000, 'Subscription: monthly plan', 'subscription')

inv = ddb.Table('invoices')
r = inv.query(KeyConditionExpression=C.Key('pk').eq(pk) & C.Key('sk').begins_with('INV#'))
for it in r.get('Items', []):
    if it.get('demo_seed'):
        inv.delete_item(Key={'pk': pk, 'sk': it['sk']})

def put_invoice(num, itype, cents, desc, ts):
    n = 'INV-2026-' + str(num).zfill(5)
    inv.put_item(Item={
        'pk': pk, 'sk': 'INV#' + n, 'invoice_id': 'inv_' + uuid.uuid4().hex,
        'invoice_number': n, 'user_sub': '${aliceSub}', 'invoice_type': itype,
        'amount_cents': cents, 'tax_cents': 0, 'total_cents': cents, 'currency': 'usd',
        'status': 'generated', 'seller_name': 'Platform', 'buyer_name': 'Alice Example',
        'buyer_email': '${aliceSub}',
        'line_items': [{'description': desc, 'quantity': 1, 'amount_cents': cents}],
        'payment_method_summary': 'Visa 4242', 'created_at': ts,
        'GSI1PK': 'USER#${aliceSub}#TYPE#' + itype, 'GSI1SK': ts,
        'GSI2PK': 'ADMIN_ALL', 'GSI2SK': ts, 'demo_seed': True,
    })

iv = ts_at(2026, 4, 1)
put_invoice(1, 'subscription', 2000, 'Gold subscription monthly', iv + 3)
put_invoice(2, 'unlock', 500, 'Unlock premium post', iv + 2)
put_invoice(3, 'tip', 1000, 'Tip to a creator', iv + 1)
print('SEEDED')
`);

  // ── Generate the tax artifacts via the real production endpoints ──────────
  await injectAuth(page, "alice");
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(800);
  await api(page, "post", "/ui/tax-forms/w9", "alice", {
    legal_name: "Alice Example",
    tin: "123456789",
    tin_type: "ssn",
    address_line1: "1 Test Street",
    city: "Testville",
    state: "CA",
    zip_code: "90001",
    certified: true,
  }).catch(() => {});
  await api(page, "post", "/ui/tax-forms/1099s/2025/generate", "alice").catch(() => {});
  await api(page, "post", "/ui/tax-documents/generate", "alice", {
    year: 2026,
    regenerate: true,
  }).catch(() => {});

  // ── 1. Intro ──────────────────────────────────────────────────────────────
  await titleCard(
    page,
    19,
    "Accounting & Taxes",
    "Spending summaries · 1099-NEC forms · itemized invoices",
  );

  // ── 2. Consumer tax documents ─────────────────────────────────────────────
  await page.goto(`${BASE}/billing/tax-documents`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1600);
  await reveal(
    page,
    page.getByRole("heading", { name: "Tax Documents" }).first(),
    "Tax documents",
    "An annual, categorized summary of everything a member spent",
    { ms: 3800 },
  );
  await reveal(
    page,
    page.getByText(/earnings summary/i).first(),
    "Categorized totals",
    "Subscriptions, tips, purchases, unlocks and deposits — broken out by category",
    { ms: 4800 },
  ).catch(() => {});
  await reveal(
    page,
    page.getByText(/document history/i).first(),
    "Downloadable record",
    "Generate a signed PDF summary for any year — archived in your history",
    { ms: 4200 },
  ).catch(() => {});

  // ── 3. 1099-NEC creator earnings forms ────────────────────────────────────
  await page.goto(`${BASE}/billing/tax-forms`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1600);
  await reveal(
    page,
    page.getByRole("heading", { name: /tax forms/i }).first(),
    "1099-NEC forms",
    "Creators who earn $600+ in a year get an automatic 1099-NEC",
    { ms: 4200 },
  );
  await reveal(
    page,
    page.getByText(/your 1099 forms/i).first(),
    "Issued forms",
    "Each year's nonemployee-compensation form, ready to file",
    { ms: 4000 },
  ).catch(() => {});
  await reveal(
    page,
    page.getByText("2025", { exact: true }).first(),
    "The 2025 form",
    "$700 in earnings cleared the threshold — the form is generated and signed",
    { ms: 4500 },
  ).catch(() => {});

  // ── 4. Invoices ────────────────────────────────────────────────────────────
  await page.goto(`${BASE}/billing/invoices`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1600);
  await reveal(
    page,
    page.getByRole("heading", { name: "Invoices" }).first(),
    "Invoices",
    "Every transaction produces an itemized invoice with a downloadable PDF",
    { ms: 4000 },
  );
  await reveal(
    page,
    page.getByText(/INV-2026/i).first(),
    "Itemized & numbered",
    "Sequential invoice numbers, line items, and per-type filtering",
    { ms: 5000 },
  ).catch(() => {});

  // ── 5. Outro ────────────────────────────────────────────────────────────────
  await caption(page, "Accounting & Taxes ✓", "Compliant paperwork, generated automatically");
  await beat(page, 3000);
  await clearCaption(page);
  await beat(page, 800);
});
