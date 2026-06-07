/**
 * Lock-in regression spec for the i18n infrastructure (GAP-0320).
 *
 * The i18n core deliverable (install packages, create config, wire into the app,
 * enable t()) is already built. These are source-assertion tests (offline, no
 * dev stack required) that lock the infrastructure against regression. They mirror
 * the `readFileSync` source-assertion style used in `e2e/alerts.spec.ts`.
 *
 * NOTE: this intentionally does NOT assert per-string migration of all TSX files —
 * that is an incremental, out-of-scope migration. It only locks the wiring.
 */

import { test, expect } from "@playwright/test";
import { readFileSync, existsSync } from "fs";

const ROOT = "/home/ubuntu/testlogon/frontend";

function read(rel: string): string {
  return readFileSync(`${ROOT}/${rel}`, "utf-8");
}

test.describe("i18n infrastructure lock-in", () => {
  test("package.json declares the four i18n packages", () => {
    const pkg = JSON.parse(read("package.json"));
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    for (const name of [
      "i18next",
      "i18next-browser-languagedetector",
      "i18next-http-backend",
      "react-i18next",
    ]) {
      expect(deps[name], `${name} should be a declared dependency`).toBeTruthy();
    }
  });

  test("src/i18n/index.ts exists and registers en/es/fr with fallbackLng en", () => {
    expect(existsSync(`${ROOT}/src/i18n/index.ts`)).toBe(true);
    const src = read("src/i18n/index.ts");

    // Resource bundles registered for each supported locale.
    expect(src).toMatch(/import\s+en\s+from\s+["'].\/locales\/en(\.json)?["']/);
    expect(src).toMatch(/import\s+es\s+from\s+["'].\/locales\/es(\.json)?["']/);
    expect(src).toMatch(/import\s+fr\s+from\s+["'].\/locales\/fr(\.json)?["']/);

    expect(src).toContain("en: { translation: en }");
    expect(src).toContain("es: { translation: es }");
    expect(src).toContain("fr: { translation: fr }");

    // Fallback + detector + react-i18next plumbing.
    expect(src).toMatch(/fallbackLng:\s*["']en["']/);
    expect(src).toContain("initReactI18next");
    expect(src).toContain("LanguageDetector");
  });

  test("each supported locale has a resource bundle file", () => {
    for (const code of ["en", "es", "fr"]) {
      const path = `src/i18n/locales/${code}.json`;
      expect(existsSync(`${ROOT}/${path}`), `${path} should exist`).toBe(true);
      // Must be valid, non-empty JSON.
      const obj = JSON.parse(read(path));
      expect(Object.keys(obj).length).toBeGreaterThan(0);
    }
  });

  test("main.tsx imports ./i18n to initialize the instance", () => {
    const src = read("src/main.tsx");
    expect(src).toMatch(/import\s+["']\.\/i18n["']/);
  });

  test("known consumers use useTranslation", () => {
    const consumers = [
      "src/components/shared/LanguageSwitcher.tsx",
      "src/components/layout/Sidebar.tsx",
      "src/components/layout/MobileNav.tsx",
      "src/components/layout/RTLProvider.tsx",
      "src/pages/settings/SettingsPage.tsx",
    ];
    for (const rel of consumers) {
      expect(existsSync(`${ROOT}/${rel}`), `${rel} should exist`).toBe(true);
      expect(read(rel), `${rel} should call useTranslation`).toContain(
        "useTranslation",
      );
    }
  });
});
