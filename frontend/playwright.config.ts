import { defineConfig, devices } from "@playwright/test";
import path from "path";
import { fileURLToPath } from "url";

// __dirname is not defined when the config is loaded as an ES module.
const HERE = path.dirname(fileURLToPath(import.meta.url));

// Resolve the F2/W2 storageState files (written by e2e/auth.setup.ts).
const cppAuth = (f) => path.resolve(HERE, "e2e", ".cpp-auth", `${f}.storageState.json`);

// Only chain the cpp auth-setup project when targeting the C++ backend, so the
// default Python run is unchanged.
const usingCpp =
  process.env.E2E_USE_CPP === "1" ||
  (!!process.env.E2E_API_BASE && !/localhost:8000\/?$/.test(process.env.E2E_API_BASE));

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  expect: { timeout: 8_000 },
  retries: 1,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:3000",
    headless: true,
    viewport: { width: 1280, height: 800 },
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
    screenshot: "only-on-failure",
    video: "off",
    ignoreHTTPSErrors: true,
  },
  projects: usingCpp
    ? [
        {
          name: "setup",
          testMatch: /auth\.setup\.ts/,
        },
        {
          name: "chromium",
          use: {
            ...devices["Desktop Chrome"],
            storageState: cppAuth("admin"),
          },
          dependencies: ["setup"],
        },
      ]
    : [
        {
          name: "chromium",
          use: { ...devices["Desktop Chrome"] },
        },
      ],
});
