/**
 * VIDEO SEGMENT 23 — Theming & Customization  (~1.5 min)
 *
 * Everything a user can change about how the app looks and feels, applied LIVE
 * on camera (no reload):
 *   - Light / Dark / System theme  → the whole app recolors instantly
 *   - Accent color swatches        → buttons, links, focus rings recolor
 *   - Font size & density          → text scales, spacing tightens/loosens
 *   - High-contrast accessibility toggle
 *   - Language / locale (i18n)     → the UI re-labels itself in Spanish, then back
 *   - The dedicated Theme Customization page with curated presets + live preview
 *
 * No seeding — every preference is client-side state with a debounced server
 * sync, so each change is visible on screen the instant it's made.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg23-theming.demo.ts
 */
import { test } from "@playwright/test";
import { BASE, injectAuth, caption, clearCaption, titleCard, beat, reveal } from "./_demo";

test("Segment 23 — Theming & Customization", async ({ page }) => {
  test.setTimeout(600_000);

  await injectAuth(page, "alice");
  await page.goto(`${BASE}/settings`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1400);

  // ── 1. Intro ────────────────────────────────────────────────────────────
  await titleCard(
    page,
    23,
    "Theming & Customization",
    "Light / dark · accent colors · density · accessibility · 3 languages",
  );

  // ── 2. Theme mode — light / dark / system (live recolor) ─────────────────
  await reveal(
    page,
    page.getByText("Appearance", { exact: true }).first(),
    "Make it yours",
    "Appearance, color, density and language — all saved to your account",
    { ms: 3500 },
  );

  // Click through System → Dark → Light so the app visibly recolors on camera.
  const clickBtn = async (name: string) =>
    page.getByRole("button", { name, exact: true }).first().click().catch(() => {});

  await caption(page, "Dark mode", "One click recolors the entire app instantly");
  await clickBtn("Dark");
  await beat(page, 3200);
  await caption(page, "Light mode", "…and back — the preference follows you across devices");
  await clickBtn("Light");
  await beat(page, 3000);
  await clickBtn("Dark"); // leave it in dark for the rest of the tour
  await beat(page, 1800);

  // ── 3. Accent color (live) ───────────────────────────────────────────────
  await reveal(
    page,
    page.getByText("Accent Color").first(),
    "Accent color",
    "Pick the color used for buttons, links and highlights",
    { ms: 3000 },
  ).catch(() => {});
  for (const [color, sub] of [
    ["Purple", "Every primary control recolors in real time"],
    ["Orange", "Preview the look before you commit"],
    ["Teal", "Seven curated swatches — or paste any hex code"],
  ] as Array<[string, string]>) {
    await caption(page, `${color} accent`, sub);
    await clickBtn(color);
    await beat(page, 2600);
  }

  // ── 4. Font size & density (live) ────────────────────────────────────────
  await reveal(
    page,
    page.getByText("Font Size").first(),
    "Font size",
    "Scale all text up or down for comfortable reading",
    { ms: 2800 },
  ).catch(() => {});
  await caption(page, "Larger text", "Accessibility built in — everything scales together");
  await clickBtn("Large");
  await beat(page, 2800);
  await clickBtn("Default");
  await beat(page, 1400);

  await reveal(
    page,
    page.getByText("Density", { exact: true }).first(),
    "Density",
    "Compact to fit more, or spacious for breathing room",
    { ms: 2800 },
  ).catch(() => {});
  await caption(page, "Compact density", "Tighten spacing to see more at once");
  await clickBtn("Compact");
  await beat(page, 2600);
  await clickBtn("Comfortable");
  await beat(page, 1400);

  // ── 5. High contrast (accessibility) ─────────────────────────────────────
  await reveal(
    page,
    page.getByText("High Contrast").first(),
    "High contrast",
    "Thicker borders and fuller-opacity text for readability",
    { ms: 3000 },
  ).catch(() => {});
  await page.getByRole("switch").first().click().catch(() => {});
  await beat(page, 2400);
  await page.getByRole("switch").first().click().catch(() => {});
  await beat(page, 1200);

  // ── 6. Language / locale (i18n) — UI re-labels live ──────────────────────
  await reveal(
    page,
    page.getByText("Language", { exact: true }).first(),
    "Speak their language",
    "The interface is fully translated — English, Spanish and French",
    { ms: 3200 },
  ).catch(() => {});
  // Open the language dropdown and switch to Spanish.
  await page
    .getByRole("combobox")
    .filter({ hasText: /english/i })
    .first()
    .click()
    .catch(() => {});
  await page.waitForTimeout(700);
  await caption(page, "Switching to Español", "Watch the navigation and labels re-render instantly");
  await page.getByRole("option", { name: /español|spanish/i }).first().click().catch(() => {});
  await beat(page, 3600);
  // Back to English.
  await page
    .getByRole("combobox")
    .filter({ hasText: /español|spanish|english/i })
    .first()
    .click()
    .catch(() => {});
  await page.waitForTimeout(700);
  await page.getByRole("option", { name: /english/i }).first().click().catch(() => {});
  await beat(page, 1800);

  // ── 7. Dedicated theme page — presets + live preview ─────────────────────
  await page.goto(`${BASE}/settings/theme`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(1400);
  await reveal(
    page,
    page.getByText("Theme Customization").first(),
    "Theme studio",
    "A dedicated page with curated presets and a live preview pane",
    { ms: 3500 },
  ).catch(() => {});
  await reveal(
    page,
    page.getByText("Preview", { exact: true }).first(),
    "Live preview",
    "See every change reflected before you save",
    { ms: 3000 },
  ).catch(() => {});
  for (const [preset, sub] of [
    ["Midnight", "Curated palettes give the whole app a new mood"],
    ["Ocean", "Pick a preset, then fine-tune to taste"],
  ] as Array<[string, string]>) {
    await caption(page, `${preset} preset`, sub);
    await clickBtn(preset);
    await beat(page, 3000);
  }

  // ── 8. Outro ─────────────────────────────────────────────────────────────
  await caption(page, "Theming & Customization ✓", "A platform that adapts to every user");
  await beat(page, 3000);
  await clearCaption(page);
  await beat(page, 800);
});
