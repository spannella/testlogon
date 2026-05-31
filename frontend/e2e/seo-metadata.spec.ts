import { test, expect } from "@playwright/test";

// PLATFORM-005: SEO / OpenGraph metadata.
//
// The /seo/* endpoints are PUBLIC (no authentication). They only ever return
// metadata for genuinely public resources; private / missing / locked content
// yields generic default metadata and must never leak private content.
//
// Section 1: Public SEO metadata API (no auth)
// Section 2: robots.txt / sitemap.xml helpers
// Section 3: Client-side <SeoHead> document.title / meta on a public page

const DEFAULT_TITLE = "Control Panel";

test.describe("PLATFORM-005 SEO metadata API (public, no auth)", () => {
  test("metadata endpoint resolves a live resource by type+id", async ({ request }) => {
    const resp = await request.get("/seo/metadata", {
      params: { type: "live", id: "sess_e2e_1" },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.title).toContain("Live Stream");
    expect(body.og["og:type"]).toBe("video.other");
    expect(body.og["og:site_name"]).toBe(DEFAULT_TITLE);
    expect(body.twitter["twitter:card"]).toBeTruthy();
    expect(body.json_ld).toBeTruthy();
    expect(body.json_ld["@type"]).toBe("BroadcastEvent");
  });

  test("metadata endpoint resolves by URL path", async ({ request }) => {
    const resp = await request.get("/seo/metadata", {
      params: { path: "/live/sess_e2e_2" },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.resource_type).toBe("live");
    expect(body.canonical_url).toContain("/live/sess_e2e_2");
  });

  test("missing / unknown profile returns default metadata (no private leak)", async ({
    request,
  }) => {
    const resp = await request.get("/seo/metadata", {
      params: { type: "profile", id: `no_such_user_${Date.now()}` },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    // Privacy: unknown resources yield generic defaults, never real data.
    expect(body.available).toBe(false);
    expect(body.title).toBe(DEFAULT_TITLE);
    expect(body.og["og:type"]).toBe("website");
  });

  test("missing post returns default metadata, never a body excerpt", async ({
    request,
  }) => {
    const resp = await request.get("/seo/metadata", {
      params: { type: "post", id: `p_missing_${Date.now()}` },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.available).toBe(false);
    expect(body.title).toBe(DEFAULT_TITLE);
  });

  test("unknown path returns site default metadata", async ({ request }) => {
    const resp = await request.get("/seo/metadata", {
      params: { path: "/totally/unknown/route" },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.available).toBe(false);
    expect(body.title).toBe(DEFAULT_TITLE);
  });

  test("meta-tags endpoint renders an HTML <meta> block", async ({ request }) => {
    const resp = await request.get("/seo/meta-tags", {
      params: { type: "live", id: "sess_e2e_3" },
    });
    expect(resp.status()).toBe(200);
    const html = await resp.text();
    expect(html).toContain("<title>");
    expect(html).toContain('property="og:title"');
    expect(html).toContain('name="twitter:card"');
    expect(html).toContain("application/ld+json");
  });

  test("meta-tags endpoint HTML-escapes content (no raw script breakout)", async ({
    request,
  }) => {
    // Even if a value contained markup, output must be escaped. The default
    // (missing) resource is safe; we assert no unescaped <script>alert pattern.
    const resp = await request.get("/seo/meta-tags", {
      params: { path: "/u/<script>alert(1)</script>" },
    });
    expect(resp.status()).toBe(200);
    const html = await resp.text();
    expect(html).not.toContain("<script>alert(1)</script>");
  });
});

test.describe("PLATFORM-005 robots & sitemap helpers", () => {
  test("robots.txt allows public routes and blocks private ones", async ({
    request,
  }) => {
    const resp = await request.get("/seo/robots.txt");
    expect(resp.status()).toBe(200);
    const text = await resp.text();
    expect(text).toContain("Allow: /u/");
    expect(text).toContain("Disallow: /messages");
    expect(text).toContain("Disallow: /billing");
  });

  test("sitemap.xml is valid XML with public landing routes", async ({
    request,
  }) => {
    const resp = await request.get("/seo/sitemap.xml");
    expect(resp.status()).toBe(200);
    const text = await resp.text();
    expect(text.trim().startsWith("<?xml")).toBe(true);
    expect(text).toContain("<urlset");
    expect(text).toContain("<loc>");
  });
});

test.describe("PLATFORM-005 client-side SeoHead", () => {
  test("app sets a document title via Helmet", async ({ page }) => {
    await page.goto("/login");
    // The default <SeoHead> (or page-specific Helmet) sets a non-empty title.
    await expect.poll(async () => (await page.title()).length).toBeGreaterThan(0);
  });

  test("default description meta tag is present", async ({ page }) => {
    await page.goto("/login");
    const desc = page.locator('meta[name="description"]').first();
    await expect(desc).toHaveAttribute("content", /.+/);
  });
});
