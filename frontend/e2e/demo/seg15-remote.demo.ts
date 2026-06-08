/**
 * VIDEO SEGMENT 15 — Remote Terminals (VNC / SSH)  (~60-95s)
 *
 * A guided tour of the platform's browser-based remote-access stack:
 *   - Host inventory (/remote/hosts): saved remote hosts grouped by environment,
 *     each with label, hostname:port, protocol badge (SSH / VNC / RDP) and a
 *     one-click Quick-Connect action.
 *   - Connect surfaces:
 *       · the noVNC "Connect Viewer" form (/remote-desktop) — brokered VNC with a
 *         target id, host/port, and an auth-input mode selector (session token vs
 *         password — secrets never persisted).
 *       · stored-key SSH auth — the SSH key manager, where a key is generated /
 *         uploaded once and then referenced by id (the browser never sees the PEM).
 *   - Multi-hop bastion (/remote/bastion): an ordered jump-host chain
 *     (Platform → Bastion → Target) that the server tunnels through, plus the
 *     resolved ProxyJump / ssh_config config.
 *   - Session recordings (/remote/recordings): every SSH session is captured as an
 *     asciicast and replayed in-browser (host, user, duration, size + a player).
 *
 * The actual live VNC/SSH connect needs a real target (unavailable in dev), so this
 * segment SHOWS the surfaces rather than driving a live terminal — exactly what the
 * brief asks for.
 *
 * Pattern mirrors seg14-vod.demo.ts: ONE long test, paced with beat() and narrated
 * with caption()/titleCard(). Everything shown is brought on-screen and PROVEN
 * visible via reveal()'s toBeInViewport assertion.
 *
 * Cast (sessions seeded by e2e_admin_session_setup.py, loaded via loadSessions):
 *   - alice — owns the seeded hosts, the SSH key, the bastion path, and the recording.
 *
 * Seeding (all off-camera, before any UI is shown, via CSRF API calls):
 *   - A handful of hosts in host inventory (SSH + VNC, grouped).
 *   - An SSH key (generated server-side; only the id is referenced).
 *   - A 2-hop bastion path through a PUBLIC bastion hostname to a target.
 *   - An SSH session recording (start → append asciicast events → stop) so the
 *     recordings table + playback surface are real.
 *
 * Run: npx playwright test -c playwright.demo.config.ts e2e/demo/seg15-remote.demo.ts
 */
import { test, expect, type APIResponse, type Page } from "@playwright/test";
import {
  BASE,
  API,
  injectAuth,
  caption,
  clearCaption,
  titleCard,
  beat,
  reveal,
  loadSessions,
  type SessionData,
} from "./_demo";

const ALICE = "alice";
const STAMP = Date.now();

async function jsonOk(resp: APIResponse, what: string): Promise<any> {
  if (!resp.ok()) throw new Error(`${what} failed: ${resp.status()} ${await resp.text()}`);
  return resp.json();
}

/** CSRF-authenticated request helper bound to one identity's cookies/token. */
function reqs(page: Page, sess: SessionData) {
  return {
    post: (path: string, body?: unknown) =>
      page.request.post(`${API}${path}`, {
        headers: { "x-csrf-token": sess.csrf_token, "content-type": "application/json" },
        data: body ?? {},
      }),
    get: (path: string) => page.request.get(`${API}${path}`),
  };
}

test("Segment 15 — Remote Terminals", async ({ page }) => {
  test.setTimeout(600_000);
  const sessions = loadSessions();
  const alice: SessionData = sessions[ALICE];

  await injectAuth(page, ALICE);
  await page.goto(`${BASE}/`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(600);
  const a = reqs(page, alice);

  // ── Off-camera seeding ──────────────────────────────────────────────────────

  // 0. Idempotency: clear any rows left by a previous run of this segment so the
  //    surfaces stay clean (one bastion path, exactly the seeded hosts, etc.).
  try {
    const existingHosts = await jsonOk((await a.get("/ui/hosts")) as APIResponse, "list hosts");
    for (const h of existingHosts.hosts ?? []) {
      if (["Production", "Staging", "Support"].includes(h.group ?? "")) {
        await page.request.delete(`${API}/ui/hosts/${h.host_id}`, {
          headers: { "x-csrf-token": alice.csrf_token },
        });
      }
    }
    const existingPaths = await jsonOk(
      (await a.get("/ui/compute/bastion/paths")) as APIResponse,
      "list paths",
    );
    for (const p of existingPaths.paths ?? []) {
      if ((p.label ?? "").startsWith("prod-db via bastion")) {
        await page.request.delete(`${API}/ui/compute/bastion/paths/${p.path_id}`, {
          headers: { "x-csrf-token": alice.csrf_token },
        });
      }
    }
    const existingRecs = await jsonOk(
      (await a.get("/ui/compute/ssh-recordings")) as APIResponse,
      "list recordings",
    );
    for (const r of existingRecs.recordings ?? []) {
      await page.request.delete(`${API}/ui/compute/ssh-recordings/${r.recording_id}`, {
        headers: { "x-csrf-token": alice.csrf_token },
      });
    }
    const existingKeys = await jsonOk(
      (await a.get("/ui/remote/ssh-keys")) as APIResponse,
      "list ssh keys",
    );
    for (const k of existingKeys.keys ?? []) {
      if ((k.label ?? "").startsWith("demo-key-")) {
        await page.request.delete(`${API}/ui/remote/ssh-keys/${k.key_id}`, {
          headers: { "x-csrf-token": alice.csrf_token },
        });
      }
    }
  } catch {
    // Best-effort cleanup; never fail the take on it.
  }

  // 1. A handful of hosts — a couple of SSH boxes + a VNC desktop, grouped.
  const hostsToSeed = [
    { label: "Prod Web 1", hostname: "10.0.1.10", protocol: "ssh", port: 22, username: "ubuntu", group: "Production", os_type: "linux", tags: ["web", "prod"] },
    { label: "Prod DB 1", hostname: "10.0.2.20", protocol: "ssh", port: 22, username: "postgres", group: "Production", os_type: "linux", tags: ["db", "prod"] },
    { label: "Support Desktop", hostname: "vnc-host.internal", protocol: "vnc", port: 5900, username: "agent", group: "Support", os_type: "linux", tags: ["desktop"] },
    { label: "Staging App", hostname: "10.0.5.30", protocol: "ssh", port: 22, username: "deploy", group: "Staging", os_type: "linux", tags: ["app"] },
  ];
  for (const h of hostsToSeed) {
    await jsonOk((await a.post("/ui/hosts", h)) as APIResponse, `create host ${h.label}`);
  }

  // 2. An SSH key generated server-side — only its id is ever referenced (the PEM
  //    never reaches the browser). Used for stored-key auth.
  let sshKeyId = "";
  try {
    const key = await jsonOk(
      (await a.post("/ui/remote/ssh-keys/generate", {
        label: `demo-key-${STAMP}`,
        key_type: "ed25519",
      })) as APIResponse,
      "generate ssh key",
    );
    sshKeyId = key.key_id ?? key.ssh_key_id ?? "";
  } catch {
    // Non-fatal: the stored-key narration still shows the key-manager surface.
  }

  // 3. A 2-hop bastion path through a PUBLIC bastion → target (post-SSRF-hardening
  //    requires public hostnames).
  await jsonOk(
    (await a.post("/ui/compute/bastion/paths", {
      label: `prod-db via bastion (${STAMP})`,
      description: "Reach the locked-down database through the public jump host.",
      jump_hops: [
        {
          hostname: "bastion.demo.example.com",
          port: 22,
          username: "ubuntu",
          ssh_key_id: sshKeyId || "key-bastion",
          label: "Edge bastion",
        },
      ],
      target: {
        hostname: "db.demo.example.com",
        port: 22,
        username: "postgres",
        ssh_key_id: sshKeyId || "key-target",
        label: "Prod DB",
      },
    })) as APIResponse,
    "create bastion path",
  );

  // 4. An SSH session recording: start → append asciicast events → stop. Gives the
  //    recordings table a real row + a playable asciicast.
  const rec = await jsonOk(
    (await a.post("/ui/compute/ssh-recordings", {
      hostname: "10.0.1.10",
      port: 22,
      username: "ubuntu",
      terminal_cols: 80,
      terminal_rows: 24,
    })) as APIResponse,
    "start recording",
  );
  const recordingId: string = rec.recording_id;
  const transcript: Array<[number, string]> = [
    [0.0, "Last login: " + new Date().toUTCString() + "\r\n"],
    [0.4, "ubuntu@prod-web-1:~$ "],
    [0.9, "uptime\r\n"],
    [1.2, " 14:02:51 up 37 days,  3:11,  2 users,  load average: 0.18, 0.21, 0.19\r\n"],
    [1.6, "ubuntu@prod-web-1:~$ "],
    [2.1, "systemctl status nginx | head -3\r\n"],
    [2.6, "[32m●[0m nginx.service - A high performance web server\r\n"],
    [2.9, "     Active: [32mactive (running)[0m since Mon 2026-05-04 10:51:02 UTC\r\n"],
    [3.4, "ubuntu@prod-web-1:~$ "],
    [4.0, "exit\r\n"],
  ];
  await jsonOk(
    (await a.post(`/ui/compute/ssh-recordings/${recordingId}/events`, {
      events: transcript.map(([offset, data]) => ({ offset, type: "o", data })),
    })) as APIResponse,
    "append recording events",
  );
  await jsonOk(
    (await a.post(`/ui/compute/ssh-recordings/${recordingId}/stop`)) as APIResponse,
    "stop recording",
  );

  // ── On-camera tour ──────────────────────────────────────────────────────────

  // 1. Intro ───────────────────────────────────────────────────────────────────
  await titleCard(
    page,
    15,
    "Remote Terminals",
    "Browser VNC & SSH · host inventory · multi-hop bastion · session recording",
    3600,
  );

  // 2. Host inventory ───────────────────────────────────────────────────────────
  await caption(page, "Host inventory", "Loading your saved remote hosts…");
  await page.goto(`${BASE}/remote/hosts`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Host Inventory" })).toBeVisible({ timeout: 12_000 });
  await page.waitForResponse((rsp) => rsp.url().includes("/ui/hosts") && rsp.status() === 200).catch(() => {});
  await page.waitForTimeout(800);
  await reveal(
    page,
    page.getByRole("heading", { name: "Host Inventory" }).first(),
    "One inventory for every box",
    "Save SSH, VNC, and RDP hosts once — grouped by environment for fast quick-connect",
    { ms: 3300 },
  );
  await reveal(
    page,
    page.getByText("Prod Web 1").first(),
    "Hostname & protocol at a glance",
    "Each row shows the label, hostname:port, and protocol — SSH or VNC",
    { ms: 3400 },
  );
  await reveal(
    page,
    page.getByText("Support Desktop").first(),
    "Mixed protocols, one list",
    "A VNC support desktop sits right alongside the SSH servers",
    { ms: 3200 },
  );
  // The quick-connect plug action on the first row.
  await reveal(
    page,
    page.getByTestId("host-connect").first(),
    "One-click quick-connect",
    "The plug launches a brokered session straight into the browser terminal",
    { ms: 3300 },
  );

  // 3. Connect — VNC viewer form ────────────────────────────────────────────────
  await caption(page, "Connect: browser VNC", "Opening the noVNC connection form…");
  await page.goto(`${BASE}/remote-desktop`, { waitUntil: "domcontentloaded" });
  await expect(page.getByText("noVNC Connection Form")).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(700);
  await reveal(
    page,
    page.getByText("noVNC Connection Form").first(),
    "Brokered noVNC in the browser",
    "No client to install — a target id opens a validated, brokered VNC viewer",
    { ms: 3400 },
  );
  // Open the auth-mode selector so the auth options are on screen.
  await page.getByTestId("vnc-auth-mode").click().catch(() => {});
  await page.waitForTimeout(600);
  await reveal(
    page,
    page.getByText("Session token (recommended)").first(),
    "Auth modes — secrets stay safe",
    "Use a short-lived session token, or a one-off password that is never persisted",
    { ms: 3600 },
  );
  await page.keyboard.press("Escape").catch(() => {});
  await page.waitForTimeout(400);

  // 3b. Connect — stored-key SSH auth ───────────────────────────────────────────
  await caption(page, "Connect: stored-key SSH", "Keys live server-side, referenced by id…");
  await page.goto(`${BASE}/remote/ssh-keys`, { waitUntil: "domcontentloaded" });
  await expect(page.getByText("SSH Keys", { exact: true })).toBeVisible({ timeout: 12_000 });
  await page.waitForTimeout(800);
  // Reveal the SSH-keys page title (generated/uploaded keys referenced by id).
  const sshKeysHeading = page.getByText("SSH Keys", { exact: true }).first();
  await reveal(
    page,
    sshKeysHeading,
    "Stored-key SSH auth",
    "Generate or upload a key once — SSH connects reference it by id; the PEM never reaches the browser",
    { ms: 3200 },
  );

  // 4. Multi-hop bastion ────────────────────────────────────────────────────────
  await caption(page, "Multi-hop bastion", "Opening the jump-host chain…");
  await page.goto(`${BASE}/remote/bastion`, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "SSH Bastion Paths" })).toBeVisible({ timeout: 12_000 });
  await page.waitForResponse((rsp) => rsp.url().includes("/ui/compute/bastion") && rsp.status() === 200).catch(() => {});
  await page.waitForTimeout(800);
  await reveal(
    page,
    page.getByRole("heading", { name: "SSH Bastion Paths" }).first(),
    "Reach locked-down hosts",
    "Define an ordered chain of jump hosts that the server tunnels through to a target",
    { ms: 3300 },
  );
  // The hop chain on the seeded path card.
  await reveal(
    page,
    page.getByTestId("bastion-path-row").first(),
    "Platform → Bastion → Target",
    "Each hop is shown end to end — the database is only reachable via the public bastion",
    { ms: 3200 },
  );
  await reveal(
    page,
    page.getByText("db.demo.example.com").first(),
    "The final target",
    "The chain terminates at the protected host — connected to entirely from the browser",
    { ms: 3200 },
  );

  // 5. Session recordings ───────────────────────────────────────────────────────
  await caption(page, "Session recordings", "Every SSH session is captured…");
  await page.goto(`${BASE}/remote/recordings`, { waitUntil: "domcontentloaded" });
  await expect(page.getByText("Session Recordings")).toBeVisible({ timeout: 12_000 });
  await page.waitForResponse((rsp) => rsp.url().includes("/ui/compute/ssh-recordings") && rsp.status() === 200).catch(() => {});
  await page.waitForTimeout(800);
  await reveal(
    page,
    page.getByText("Session Recordings").first(),
    "Tamper-evident session capture",
    "Every SSH session is recorded server-side as an asciicast — host, user, duration, and size",
    { ms: 3400 },
  );
  await reveal(
    page,
    page.getByTestId("ssh-recording-row").first(),
    "A captured session",
    "This recording was made off the prod-web-1 host as ubuntu",
    { ms: 2800 },
  );
  // Open the in-browser player.
  await page.getByTestId("ssh-recording-play").first().click().catch(() => {});
  await page.waitForTimeout(900);
  await reveal(
    page,
    page.getByTestId("ssh-recording-player-card").first(),
    "Replay it in the browser",
    "Scrub the full terminal transcript back — no external tooling, fully auditable",
    { ms: 3600, ring: false },
  );

  // 6. Outro ────────────────────────────────────────────────────────────────────
  await clearCaption(page);
  await beat(page, 500);
  await caption(page, "Remote Terminals ✓", "Next: Admin & Root");
  await beat(page, 3000);
  await clearCaption(page);
  await beat(page, 800);
});
