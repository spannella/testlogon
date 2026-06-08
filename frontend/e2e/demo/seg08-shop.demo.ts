/**
 * VIDEO SEGMENT 08 — Shop / E-commerce  (~90-120s)
 *
 * A guided tour of the built-in storefront:
 *   - The Shop catalog: a product grid of cards (name, price, image)
 *   - Adding an item to the cart from the product page
 *   - The Cart: line items + running total
 *   - A promo code applied at checkout, dropping the total
 *   - The Checkout step: order summary + payment method + Place Order
 *   - The abandoned-cart recovery concept (caption only)
 *
 * Pattern mirrors seg07-monetization.demo.ts: ONE long test, paced with beat()
 * and narrated with caption()/titleCard(). Every feature shown is brought
 * on-screen and PROVEN visible via reveal()'s toBeInViewport assertion.
 *
 * Cast (sessions seeded by e2e_admin_session_setup.py, loaded via loadSessions):
 *   - Alice — the shopper on camera. She is also the catalog creator (the demo
 *     seeds a category + 4 priced, imaged products under her account), and the
 *     checkout's promo-validation falls back to the current user as the
 *     creator_scope, so the seeded promo code (creator_scope = Alice,
 *     applies_to = ["shop"]) validates against her own cart. She also gets a
 *     saved payment method so the checkout shows a real card + Place Order.
 *
 * Seeding (all off-camera, before any UI is shown):
 *   - Catalog: category + items via the cookie+CSRF catalog API (api() helper).
 *   - Cart: a fresh OPEN cart with two line items, created via the
 *     shoppingcart API, so /cart and /cart/checkout are deterministic.
 *   - Promo: a 25%-off "shop" code via the cookie+CSRF promo-codes API.
 *   - Payment method: a Visa •••• 4242 row written straight to the billing
 *     table (DDB), set as the default, so checkout renders a selectable card.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg08-shop.demo.ts
 */
import { test, expect, type APIResponse } from "@playwright/test";
import { execSync } from "child_process";
import {
  BASE,
  injectAuth,
  api,
  caption,
  clearCaption,
  titleCard,
  beat,
  reveal,
  revealClick,
  loadSessions,
} from "./_demo";

const PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";
const ALICE = "alice";

/** Run a small inline python snippet against the local DDB (sources .env.local). */
function ddbPy(body: string): void {
  execSync(
    `${PYTHON} -c "
import boto3, os
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
  );
}

/** Seed a default Visa •••• 4242 payment method straight into the billing table. */
function seedPaymentMethod(userSub: string): void {
  ddbPy(`
import time
tbl = ddb.Table('billing')
pk = 'USER#${userSub}'
pm_id = 'pm_seg08_demo'
now = int(time.time())
tbl.put_item(Item={
    'pk': pk, 'sk': 'PM#' + pm_id, 'payment_method_id': pm_id,
    'provider': 'stripe', 'provider_method_id': pm_id, 'method_type': 'card',
    'label': 'Visa', 'brand': 'visa', 'last4': '4242',
    'exp_month': 12, 'exp_year': 2030, 'priority': 0, 'created_at': now,
})
tbl.put_item(Item={
    'pk': pk, 'sk': 'BILLING', 'autopay_enabled': False, 'currency': 'usd',
    'default_payment_method_id': pm_id,
})
`);
}

/** Small inline SVG data-URI so each product card shows a real image. */
function svgImage(label: string, bg: string): string {
  const svg =
    `<svg xmlns='http://www.w3.org/2000/svg' width='400' height='300'>` +
    `<rect width='400' height='300' fill='${bg}'/>` +
    `<text x='200' y='160' font-family='Inter,sans-serif' font-size='34' ` +
    `font-weight='700' fill='white' text-anchor='middle'>${label}</text></svg>`;
  return "data:image/svg+xml;utf8," + encodeURIComponent(svg);
}

async function jsonOk(resp: APIResponse, what: string): Promise<any> {
  if (!resp.ok()) throw new Error(`${what} failed: ${resp.status()} ${await resp.text()}`);
  return resp.json();
}

test("Segment 08 — Shop / E-commerce", async ({ page }) => {
  test.setTimeout(600_000);
  const sessions = loadSessions();
  const aliceSub = sessions[ALICE].user_sub;
  const stamp = Date.now();

  // ── Seed off camera ────────────────────────────────────────────────────────
  seedPaymentMethod(aliceSub);

  // Inject Alice's cookies into the page context so api() / page.request carry them.
  await injectAuth(page, ALICE);

  // Promo code (25% off shop checkouts). Unique per run; tolerate 409 dups.
  const promoCode = `DEMO${stamp}`.slice(0, 20).toUpperCase();
  await api(page, "post", "/ui/promo-codes", ALICE, {
    code: promoCode,
    discount_type: "percentage",
    discount_value: 25,
    applies_to: ["shop"],
    max_uses: 1000,
    max_uses_per_user: 100,
  });

  // Catalog: one category + four priced, imaged products.
  const catResp = await api(page, "post", "/ui/catalog/categories", ALICE, {
    name: "Studio Store",
    description: "Official merch and digital goods",
  });
  const categoryId = (await jsonOk(catResp as APIResponse, "create category")).category_id as string;

  const products: Array<{ name: string; price: number; img: string }> = [
    { name: "Signed Poster", price: 2500, img: svgImage("Signed Poster", "#6366f1") },
    { name: "Studio Hoodie", price: 5900, img: svgImage("Studio Hoodie", "#0ea5e9") },
    { name: "Sticker Pack", price: 800, img: svgImage("Sticker Pack", "#f59e0b") },
    { name: "Preset Bundle", price: 1900, img: svgImage("Preset Bundle", "#10b981") },
  ];
  const created: Array<{ item_id: string; name: string; price: number; img: string }> = [];
  for (const p of products) {
    const r = await api(page, "post", `/ui/catalog/categories/${categoryId}/items`, ALICE, {
      name: p.name,
      description: `${p.name} — from the Studio Store`,
      price_cents: p.price,
      currency: "USD",
      image_urls: [p.img],
      attributes: {},
    });
    const item = await jsonOk(r as APIResponse, `create item ${p.name}`);
    created.push({ item_id: item.item_id, name: p.name, price: p.price, img: p.img });
  }

  // Cart: clean out any pre-existing OPEN carts so the cart shown on camera is the
  // one this run builds (the UI "Add to cart" in beat 3 creates a fresh OPEN cart;
  // we then top it up with two more items so /cart shows a full, deterministic cart).
  const existingCarts = (await (await api(page, "get", "/ui/shoppingcart/carts", ALICE)).json()) as Array<{
    cart_id: string;
    status: string;
  }>;
  for (const c of Array.isArray(existingCarts) ? existingCarts : []) {
    if (c.status === "OPEN")
      await api(page, "delete", `/ui/shoppingcart/carts/${c.cart_id}`, ALICE);
  }

  // ── Load the shell ─────────────────────────────────────────────────────────
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1000);

  // ── 1. Intro ────────────────────────────────────────────────────────────────
  await titleCard(page, 8, "Shop", "Catalog · cart · promo codes · checkout · recovery");

  // ── 2. Shop catalog grid ─────────────────────────────────────────────────────
  await page.goto(`${BASE}/shop`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1600);
  // Make sure our category is selected so the grid is populated.
  await page.getByRole("button", { name: "Studio Store" }).first().click().catch(() => {});
  await page.waitForTimeout(1400);

  await reveal(
    page,
    page.getByRole("heading", { name: "Shop" }),
    "The Shop",
    "A full storefront built into the platform — browse, cart, and check out",
    { ms: 3800 },
  );
  await reveal(
    page,
    page.getByText("Studio Hoodie").first(),
    "Product catalog",
    "Every product is a card with its name, image, and price",
    { ms: 4500 },
  );
  await reveal(
    page,
    page.getByText("$59.00").first(),
    "Clear pricing",
    "Prices are shown up front, organized into browsable categories",
    { ms: 4200 },
  );

  // ── 3. Add to cart (from the product page) ───────────────────────────────────
  await revealClick(
    page,
    page.getByText("Signed Poster").first(),
    "Open a product",
    "Tap any product to see its full detail page",
    { ms: 3000, settleMs: 1800 },
  );
  await reveal(
    page,
    page.getByRole("button", { name: /add to cart/i }),
    "Add to cart",
    "Choose a quantity and add the item to your cart",
    { ms: 3500 },
  );
  await page.getByRole("button", { name: /add to cart/i }).click().catch(() => {});
  await page.waitForTimeout(1600);
  await reveal(
    page,
    page.getByText(/added .* to cart/i).first(),
    "Item added",
    "A confirmation pops up the moment it lands in your cart",
    { ms: 3500 },
  );

  // The UI add-to-cart created a fresh OPEN cart with the Signed Poster. Find it and
  // top it up with the Hoodie + Sticker Pack so the cart on camera is nicely full.
  const cartsNow = (await (await api(page, "get", "/ui/shoppingcart/carts", ALICE)).json()) as Array<{
    cart_id: string;
    status: string;
  }>;
  const openCart = (Array.isArray(cartsNow) ? cartsNow : []).find((c) => c.status === "OPEN");
  const cartId = openCart?.cart_id ?? "";
  for (const c of [created[1], created[2]]) {
    await api(page, "post", `/ui/shoppingcart/carts/${cartId}/items`, ALICE, {
      sku: c.item_id,
      name: c.name,
      quantity: 1,
      unit_price_cents: c.price,
      image_url: c.img,
      category_id: categoryId,
      item_id: c.item_id,
    });
  }

  // ── 4. Cart: line items + total ──────────────────────────────────────────────
  await page.goto(`${BASE}/cart?cartId=${cartId}`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1800);
  await reveal(
    page,
    page.getByText("Studio Hoodie").first(),
    "Your cart",
    "The cart lists every item with its image, price, and quantity",
    { ms: 4500 },
  );
  await reveal(
    page,
    page.getByText("Total").first(),
    "Running total",
    "Adjust quantities and the total recalculates instantly",
    { ms: 4000 },
  );
  await reveal(
    page,
    page.getByRole("button", { name: /proceed to checkout/i }),
    "Proceed to checkout",
    "One button takes you to a secure checkout",
    { ms: 3000 },
  );

  // ── 5. Checkout + promo code ─────────────────────────────────────────────────
  await page.goto(`${BASE}/cart/checkout?cartId=${cartId}`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1800);
  await reveal(
    page,
    page.getByText("Order Summary").first(),
    "Checkout",
    "The order summary itemizes exactly what you're buying",
    { ms: 4200 },
  );

  // Open the promo panel and apply the seeded code.
  await reveal(
    page,
    page.getByTestId("promo-expand-btn"),
    "Have a promo code?",
    "Discount codes are applied right at checkout",
    { ms: 3000 },
  );
  await page.getByTestId("promo-expand-btn").click().catch(() => {});
  await page.waitForTimeout(800);
  await page.getByTestId("promo-input").fill(promoCode);
  await page.waitForTimeout(700);
  await reveal(
    page,
    page.getByTestId("promo-input"),
    "Enter your code",
    `Applying ${promoCode} — 25% off this order`,
    { ms: 2800, ring: false },
  );
  await page.getByTestId("promo-apply-btn").click().catch(() => {});
  // Wait for the validation to resolve + the discount line to render.
  await expect(page.getByTestId("promo-success")).toBeVisible({ timeout: 12_000 }).catch(() => {});
  await page.waitForTimeout(1000);

  await reveal(
    page,
    page.getByTestId("promo-discount-line"),
    "Discount applied",
    "The discount drops straight off the order total",
    { ms: 4500 },
  );

  // ── 6. Payment method + Place Order ──────────────────────────────────────────
  await reveal(
    page,
    page.getByText("Payment Method").first(),
    "Payment method",
    "Pay with a saved card — here, Visa ending 4242",
    { ms: 4000 },
  );
  await reveal(
    page,
    page.getByRole("button", { name: /place order/i }),
    "Place your order",
    "One tap places the order at the discounted total",
    { ms: 4200 },
  );

  // ── 7. Cart recovery (concept caption) ───────────────────────────────────────
  await caption(
    page,
    "Abandoned-cart recovery",
    "Leave a cart behind and the platform emails a one-tap recovery link to bring you back",
  );
  await beat(page, 4500);

  // ── 8. Outro ─────────────────────────────────────────────────────────────────
  await caption(page, "Shop ✓", "Next: Files & Integrations");
  await beat(page, 3200);
  await clearCaption(page);
  await beat(page, 900);
});
