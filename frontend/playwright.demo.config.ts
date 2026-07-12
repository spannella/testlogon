import { defineConfig, devices } from "@playwright/test";

/**
 * Dedicated config for the v2-verticals demo walkthrough video.
 *
 * SEPARATE from playwright.config.ts so it never runs under `just e2e` / CI.
 * Each *.demo.ts file is ONE long test that records as a single 1080p webm.
 * Run a single segment:
 *   npx playwright test --config=playwright.demo.config.ts e2e/demo/seg1-ofbiz.demo.ts
 */
export default defineConfig({
  testDir: "./e2e/demo",
  testMatch: "**/*.demo.ts",
  timeout: 600_000,
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
    video: { mode: "on", size: { width: 1920, height: 1080 } },
  },
  projects: [
    {
      name: "demo",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1920, height: 1080 } },
    },
  ],
});
