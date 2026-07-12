import { test, expect, Page } from "@playwright/test";
import { injectAuth, getSession } from "./helpers/session";

const TS = Date.now();
const BASE = "/ui/compute/connection-profiles";

let alicePage: Page;
let bobPage: Page;

async function apiPost(page: Page, path: string, body?: unknown) {
  const sess = getSession(page);
  return page.request.post(path, {
    headers: { "x-csrf-token": sess.csrf_token },
    data: body ?? {},
  });
}

async function apiGet(page: Page, path: string) {
  return page.request.get(path);
}

async function apiPatch(page: Page, path: string, body: unknown) {
  const sess = getSession(page);
  return page.request.patch(path, {
    headers: { "x-csrf-token": sess.csrf_token },
    data: body,
  });
}

async function apiDelete(page: Page, path: string) {
  const sess = getSession(page);
  return page.request.delete(path, {
    headers: { "x-csrf-token": sess.csrf_token },
  });
}

test.describe("INFRA-006 Connection Profiles & Quick Connect", () => {
  test.beforeAll(async ({ browser }) => {
    alicePage = await browser.newPage();
    await injectAuth(alicePage, "alice");
    // Seed the client-side auth store so ProtectedRoute treats the page as
    // authenticated (cookies alone only satisfy server-side API auth).
    await alicePage.goto("/login", { waitUntil: "domcontentloaded" });
    await alicePage.evaluate((uid: string) => {
      const state = { userId: uid, accessToken: null, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    }, getSession("alice").user_sub);
    bobPage = await browser.newPage();
    await injectAuth(bobPage, "bob");
  });

  test.afterAll(async () => {
    await alicePage?.close();
    await bobPage?.close();
  });

  // ─── Section: CRUD ───────────────────────────────────────────────

  test("create profile then list and get", async () => {
    const create = await apiPost(alicePage, BASE, {
      label: `cp-crud-${TS}`,
      hostname: "host-crud.example.com",
      port: 22,
      username: "ubuntu",
      auth_method: "key_ref",
      terminal_cols: 120,
      terminal_color_scheme: "monokai",
    });
    expect(create.status()).toBe(201);
    const profile = await create.json();
    expect(profile.profile_id).toBeTruthy();
    expect(profile.username).toBe("ubuntu");
    expect(profile.terminal_cols).toBe(120);
    expect(profile.terminal_color_scheme).toBe("monokai");

    const list = await apiGet(alicePage, BASE);
    expect(list.status()).toBe(200);
    const listed = await list.json();
    expect(listed.profiles.some((p: any) => p.profile_id === profile.profile_id)).toBe(true);

    const get = await apiGet(alicePage, `${BASE}/${profile.profile_id}`);
    expect(get.status()).toBe(200);
    const got = await get.json();
    expect(got.label).toBe(`cp-crud-${TS}`);
  });

  test("update profile fields", async () => {
    const create = await apiPost(alicePage, BASE, {
      label: `cp-update-${TS}`,
      hostname: "host-update.example.com",
      username: "admin",
    });
    const profile = await create.json();

    const patch = await apiPatch(alicePage, `${BASE}/${profile.profile_id}`, {
      username: "root",
      port: 2222,
      is_favorite: true,
    });
    expect(patch.status()).toBe(200);
    const updated = await patch.json();
    expect(updated.username).toBe("root");
    expect(updated.port).toBe(2222);
    expect(updated.is_favorite).toBe(true);
  });

  test("delete profile then 404", async () => {
    const create = await apiPost(alicePage, BASE, {
      label: `cp-del-${TS}`,
      hostname: "host-del.example.com",
      username: "ubuntu",
    });
    const profile = await create.json();

    const del = await apiDelete(alicePage, `${BASE}/${profile.profile_id}`);
    expect(del.status()).toBe(204);

    const get = await apiGet(alicePage, `${BASE}/${profile.profile_id}`);
    expect(get.status()).toBe(404);
  });

  // ─── Section: Quick connect ──────────────────────────────────────

  test("quick-connect resolves descriptor and bumps last_used", async () => {
    const create = await apiPost(alicePage, BASE, {
      label: `cp-qc-${TS}`,
      hostname: "host-qc.example.com",
      port: 22,
      username: "ubuntu",
      terminal_color_scheme: "dracula",
    });
    const profile = await create.json();
    expect(profile.last_used_at).toBe(0);

    const qc = await apiPost(alicePage, `${BASE}/${profile.profile_id}/quick-connect`);
    expect(qc.status()).toBe(200);
    const desc = await qc.json();
    expect(desc.hostname).toBe("host-qc.example.com");
    expect(desc.username).toBe("ubuntu");
    expect(desc.port).toBe(22);
    expect(desc.terminal_color_scheme).toBe("dracula");
    expect(desc.connected_at).toBeGreaterThan(0);

    // last_used_at bumped -> visible on GET.
    const get = await apiGet(alicePage, `${BASE}/${profile.profile_id}`);
    const got = await get.json();
    expect(got.last_used_at).toBeGreaterThan(0);
    expect(got.use_count).toBe(1);
  });

  test("favorites and recent are ordered first in the list", async () => {
    const fav = await apiPost(alicePage, BASE, {
      label: `cp-fav-${TS}`,
      hostname: "host-fav.example.com",
      username: "ubuntu",
      is_favorite: true,
    });
    const favProfile = await fav.json();

    const list = await apiGet(alicePage, BASE);
    const listed = await list.json();
    const favIdx = listed.profiles.findIndex(
      (p: any) => p.profile_id === favProfile.profile_id
    );
    const nonFavIdx = listed.profiles.findIndex((p: any) => !p.is_favorite);
    // a favorite must sort before any non-favorite (when one exists).
    if (nonFavIdx >= 0) {
      expect(favIdx).toBeLessThan(nonFavIdx);
    }
  });

  // ─── Section: Validation ─────────────────────────────────────────

  test("invalid host returns 422", async () => {
    const create = await apiPost(alicePage, BASE, {
      label: `cp-badhost-${TS}`,
      hostname: "not a valid host!!",
      username: "ubuntu",
    });
    expect(create.status()).toBe(422);
  });

  test("out-of-range terminal_cols returns 422", async () => {
    const create = await apiPost(alicePage, BASE, {
      label: `cp-badcols-${TS}`,
      hostname: "host-badcols.example.com",
      username: "ubuntu",
      terminal_cols: 10,
    });
    expect(create.status()).toBe(422);
  });

  test("invalid color scheme returns 422", async () => {
    const create = await apiPost(alicePage, BASE, {
      label: `cp-badcolor-${TS}`,
      hostname: "host-badcolor.example.com",
      username: "ubuntu",
      terminal_color_scheme: "neon",
    });
    expect(create.status()).toBe(422);
  });

  test("missing host and instance returns 422", async () => {
    const create = await apiPost(alicePage, BASE, {
      label: `cp-nohost-${TS}`,
      username: "ubuntu",
    });
    expect(create.status()).toBe(422);
  });

  test("quick-connect without username returns 400", async () => {
    const create = await apiPost(alicePage, BASE, {
      label: `cp-nouser-${TS}`,
      hostname: "host-nouser.example.com",
      protocol: "ssh",
    });
    const profile = await create.json();
    const qc = await apiPost(alicePage, `${BASE}/${profile.profile_id}/quick-connect`);
    expect(qc.status()).toBe(400);
  });

  test("reference to non-existent SSH key returns 404", async () => {
    const create = await apiPost(alicePage, BASE, {
      label: `cp-badkey-${TS}`,
      hostname: "host-badkey.example.com",
      username: "ubuntu",
      ssh_key_id: "does-not-exist",
    });
    expect(create.status()).toBe(404);
  });

  // ─── Section: Ownership isolation ────────────────────────────────

  test("profiles are user-isolated (404 across users)", async () => {
    const create = await apiPost(alicePage, BASE, {
      label: `cp-iso-${TS}`,
      hostname: "host-iso.example.com",
      username: "ubuntu",
    });
    const profile = await create.json();

    const bobGet = await apiGet(bobPage, `${BASE}/${profile.profile_id}`);
    expect(bobGet.status()).toBe(404);

    const bobPatch = await apiPatch(bobPage, `${BASE}/${profile.profile_id}`, {
      username: "hacker",
    });
    expect(bobPatch.status()).toBe(404);

    const bobDelete = await apiDelete(bobPage, `${BASE}/${profile.profile_id}`);
    expect(bobDelete.status()).toBe(404);

    const bobQc = await apiPost(bobPage, `${BASE}/${profile.profile_id}/quick-connect`);
    expect(bobQc.status()).toBe(404);
  });

  // ─── Section: UI ─────────────────────────────────────────────────

  test("management UI lists profiles and opens dialog", async () => {
    await apiPost(alicePage, BASE, {
      label: `cp-ui-${TS}`,
      hostname: "host-ui.example.com",
      username: "ubuntu",
    });
    await alicePage.goto("/remote/connection-profiles");
    await expect(
      alicePage.getByRole("heading", { name: "Connection Profiles" })
    ).toBeVisible();
    await expect(
      alicePage.locator('[data-testid="connection-profile-card"]').first()
    ).toBeVisible();
    await alicePage.getByRole("button", { name: "New Profile" }).click();
    await expect(
      alicePage.getByRole("heading", { name: "New Connection Profile" })
    ).toBeVisible();
  });
});
