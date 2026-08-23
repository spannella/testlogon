/**
 * E2E SMOKE — new trading / investing surfaces (authenticated render).
 *
 * Covers the routes added by the trading-blotter + custody/margin programs:
 *   /invest              — InvestHubPage         (h1 "Invest")
 *   /strategies          — StrategyMarketPage    (h1 "Strategies & Baskets")
 *   /tokens              — TokenMarketPage        (h1 "Creator Tokens")
 *   /bailouts            — BailoutsBoardPage      (PageHeader h1 "Bailouts")
 *   /portfolio/analytics — PortfolioAnalyticsPage (h1 "Portfolio Risk")
 *   /activity-center     — ActivityCenterPage     (h1 "Activity Center")
 *   /algos               — ActiveAlgosPage        (h1 "Active Algos")
 *   /watchlist           — WatchlistPage          (h1 "Watchlist")
 *   /reports/tax         — TaxReportPage          (h1 "Tax & Gains")
 *   /analysis            — MarketAnalysisPage     (h1 "Analysis")
 *   /custody/providers   — CustodyProvidersPage   (h1 "Custody providers")
 *
 * These are deliberately SHALLOW smoke checks: each authenticated navigation
 * must render the page's primary heading and must NOT surface the app error
 * boundary ("Something went wrong"). A degraded / empty state is acceptable —
 * the underlying edge backends may 404 in CI, and the pages are built to
 * render a heading + empty/pending state rather than crash.
 *
 * Auth: shared authenticated page via the canonical injectAuth("alice") helper
 * (same cookie + auth-store seeding every other spec uses). No API seeding —
 * these are UI-render smokes only.
 *
 * Runs in the (non-required, label-gated) web-e2e CI gate. Listed in
 * e2e/ci-gate-green.txt so the gate picks it up.
 */
import { test, expect, type Page } from "@playwright/test";
import { injectAuth, getSession } from "./helpers/session";

const BASE = "http://localhost:3000";

interface Surface {
  /** Relative app route (leading slash). */
  route: string;
  /** Case-insensitive primary-heading matcher. */
  heading: RegExp;
}

const SURFACES: Surface[] = [
  { route: "/invest", heading: /^invest$/i },
  { route: "/strategies", heading: /strategies\s*&?\s*baskets/i },
  { route: "/tokens", heading: /creator tokens/i },
  { route: "/bailouts", heading: /^bailouts$/i },
  { route: "/portfolio/analytics", heading: /portfolio risk/i },
  { route: "/activity-center", heading: /activity center/i },
  { route: "/algos", heading: /active algos/i },
  { route: "/watchlist", heading: /^watchlist$/i },
  { route: "/reports/tax", heading: /tax\s*&?\s*gains/i },
  { route: "/analysis", heading: /^analysis$/i },
  { route: "/custody/providers", heading: /custody providers/i },
];

test.describe("Trading surfaces smoke (authenticated render)", () => {
  let page: Page;

  test.beforeAll(async ({ browser }) => {
    page = await browser.newPage();
    await injectAuth(page, "alice");
    // Seed the client-side auth store so ProtectedRoute treats the page as
    // authenticated (cookies alone only satisfy server-side API auth).
    await page.goto(`${BASE}/login`, { waitUntil: "domcontentloaded" });
    await page.evaluate((uid: string) => {
      const state = { userId: uid, accessToken: null, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    }, getSession("alice").user_sub);
  });

  test.afterAll(async () => {
    await page?.close();
  });

  for (const { route, heading } of SURFACES) {
    test(`renders ${route} without crashing`, async () => {
      await page.goto(`${BASE}${route}`, { waitUntil: "domcontentloaded" });

      // Primary heading/landmark renders (generous wait: lazy chunk + first
      // data fetch). Degraded/empty state is fine; a crash is not.
      await expect(
        page.getByRole("heading", { name: heading }).first(),
      ).toBeVisible({ timeout: 20_000 });

      // The React error boundary fallback must NOT be present.
      await expect(page.getByText(/something went wrong/i)).toHaveCount(0);

      // Not bounced to the login screen (ProtectedRoute would redirect an
      // unauthenticated session).
      expect(new URL(page.url()).pathname).not.toBe("/login");
    });
  }
});
