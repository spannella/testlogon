import { defineConfig } from "@playwright/test";

/**
 * Dedicated Playwright config for the 30-minute feature-walkthrough VIDEO.
 *
 * Kept entirely separate from `playwright.config.ts` (the CI/test suite):
 *   - Test files are named `*.demo.ts` (the main config only matches `*.spec.ts`),
 *     so `just e2e` never runs these.
 *   - Records 1080p video of every segment (one webm per segment test).
 *   - Generous timeouts + 0 retries (a demo take should be deterministic; if it
 *     fails we fix the seed/beat rather than retry a half-recorded take).
 *
 * Run a single segment:
 *   npx playwright test -c playwright.demo.config.ts e2e/demo/seg01-auth.demo.ts
 * Run all segments:
 *   npx playwright test -c playwright.demo.config.ts
 */
export default defineConfig({
  testDir: "./e2e/demo",
  testMatch: "**/*.demo.ts",
  timeout: 600_000, // 10 min per segment (tours are long + paced)
  expect: { timeout: 15_000 },
  retries: 0,
  workers: 1,
  reporter: [["list"]],
  outputDir: "./e2e/demo/.artifacts",
  use: {
    baseURL: "http://localhost:3000",
    headless: true,
    viewport: { width: 1920, height: 1080 },
    actionTimeout: 20_000,
    navigationTimeout: 30_000,
    screenshot: "off",
    video: {
      mode: "on",
      size: { width: 1920, height: 1080 },
    },
  },
  projects: [
    {
      name: "demo",
      use: { viewport: { width: 1920, height: 1080 } },
    },
  ],
});
