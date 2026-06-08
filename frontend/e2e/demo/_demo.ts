/**
 * Shared helpers for the feature-walkthrough VIDEO segments.
 *
 * Recording model: each `*.demo.ts` segment is ONE long test; Playwright records
 * one 1080p webm per test (see playwright.demo.config.ts). These helpers give the
 * video deliberate pacing (`beat`) and on-screen narration (`caption`/`titleCard`)
 * so the silent recording is self-explanatory; the matching voiceover lives in
 * docs/demo-video-script.md and is muxed in later.
 */
import { execSync } from "child_process";
import { expect, type Locator, type Page } from "@playwright/test";
import { loadSessions, type SessionData } from "../helpers/session";

export { loadSessions, type SessionData };

export const BASE = "http://localhost:3000";
export const API = "http://localhost:8000";

/** Default beat length (ms). The total video length ≈ Σ of all beats. */
export const BEAT = 2600;

/** Deliberate on-screen pause so a viewer can read the caption + see the action. */
export async function beat(page: Page, ms: number = BEAT): Promise<void> {
  await page.waitForTimeout(ms);
}

/** Inject cookies + the Zustand auth-store (WITH the real access token, so role-aware
 *  UI such as admin/root-only tabs renders) for identity `key`. */
export async function injectAuth(page: Page, key = "alice"): Promise<SessionData> {
  const sess = loadSessions()[key];
  if (!sess) throw new Error(`No seeded session for identity "${key}"`);
  await page.context().addCookies(sess.cookies);
  await page.addInitScript(
    ({ uid, token }: { uid: string; token: string }) => {
      const state = { userId: uid, accessToken: token, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    { uid: sess.user_sub, token: sess.access_token },
  );
  return sess;
}

/** CSRF-authenticated API call from a page's browser context (cookies + x-csrf-token). */
export async function api(
  page: Page,
  method: "get" | "post" | "patch" | "delete" | "put",
  path: string,
  key: string,
  body?: unknown,
) {
  const sess = loadSessions()[key];
  const url = path.startsWith("http") ? path : `${API}${path}`;
  const opts: Record<string, unknown> = {
    headers: { "x-csrf-token": sess.csrf_token, "content-type": "application/json" },
  };
  if (body !== undefined) (opts as { data: unknown }).data = body;
  return (page.request as unknown as Record<string, (u: string, o: unknown) => Promise<unknown>>)[
    method
  ](url, opts);
}

/**
 * Show / update the lower-third caption banner. Self-contained per call (creates
 * the element if missing, so it survives page navigations). Pass title only, or
 * title + subtitle. pointer-events:none so it never blocks clicks.
 */
export async function caption(page: Page, title: string, subtitle = ""): Promise<void> {
  await page
    .evaluate(
      ({ title, subtitle }: { title: string; subtitle: string }) => {
        const ID = "__demo_caption";
        let el = document.getElementById(ID) as HTMLDivElement | null;
        if (!el) {
          el = document.createElement("div");
          el.id = ID;
          el.style.cssText = [
            "position:fixed",
            "left:50%",
            "bottom:48px",
            "transform:translateX(-50%)",
            "max-width:78vw",
            "z-index:2147483647",
            "pointer-events:none",
            "padding:18px 30px",
            "border-radius:16px",
            "background:linear-gradient(180deg,rgba(15,23,42,.86),rgba(15,23,42,.94))",
            "box-shadow:0 10px 40px rgba(0,0,0,.45)",
            "border:1px solid rgba(148,163,184,.35)",
            "color:#f8fafc",
            "font-family:Inter,ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif",
            "text-align:center",
            "opacity:0",
            "transition:opacity .35s ease",
          ].join(";");
          const t = document.createElement("div");
          t.id = ID + "_t";
          t.style.cssText = "font-size:30px;font-weight:700;letter-spacing:.2px;line-height:1.2";
          const s = document.createElement("div");
          s.id = ID + "_s";
          s.style.cssText =
            "font-size:19px;font-weight:400;color:#cbd5e1;margin-top:6px;line-height:1.35";
          el.appendChild(t);
          el.appendChild(s);
          document.body.appendChild(el);
        }
        (document.getElementById(ID + "_t") as HTMLDivElement).textContent = title;
        const s = document.getElementById(ID + "_s") as HTMLDivElement;
        s.textContent = subtitle;
        s.style.display = subtitle ? "block" : "none";
        requestAnimationFrame(() => {
          el!.style.opacity = "1";
        });
      },
      { title, subtitle },
    )
    .catch(() => {});
}

/** Hide the caption banner. */
export async function clearCaption(page: Page): Promise<void> {
  await page
    .evaluate(() => {
      const el = document.getElementById("__demo_caption");
      if (el) el.style.opacity = "0";
    })
    .catch(() => {});
}

/**
 * Full-screen section title card shown for `ms`, then removed. Used at the very
 * start of a segment as an in-video intro (ffmpeg also adds title cards between
 * segments during the stitch, but this makes each clip self-contained).
 */
export async function titleCard(
  page: Page,
  segNo: number,
  title: string,
  subtitle = "",
  ms = 3200,
): Promise<void> {
  await page
    .evaluate(
      ({ segNo, title, subtitle }: { segNo: number; title: string; subtitle: string }) => {
        const ID = "__demo_titlecard";
        document.getElementById(ID)?.remove();
        const el = document.createElement("div");
        el.id = ID;
        el.style.cssText = [
          "position:fixed",
          "inset:0",
          "z-index:2147483647",
          "display:flex",
          "flex-direction:column",
          "align-items:center",
          "justify-content:center",
          "gap:14px",
          "background:radial-gradient(1200px 600px at 50% 40%,rgba(30,41,59,1),rgba(2,6,23,1))",
          "color:#f8fafc",
          "font-family:Inter,ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif",
          "opacity:0",
          "transition:opacity .4s ease",
        ].join(";");
        el.innerHTML =
          `<div style="font-size:20px;letter-spacing:3px;color:#60a5fa;font-weight:600">` +
          `SECTION ${String(segNo).padStart(2, "0")}</div>` +
          `<div style="font-size:54px;font-weight:800;text-align:center;max-width:80vw">${title}</div>` +
          (subtitle
            ? `<div style="font-size:22px;color:#94a3b8;text-align:center;max-width:70vw">${subtitle}</div>`
            : "");
        document.body.appendChild(el);
        requestAnimationFrame(() => {
          el.style.opacity = "1";
        });
      },
      { segNo, title, subtitle },
    )
    .catch(() => {});
  await page.waitForTimeout(ms);
  await page
    .evaluate(() => {
      const el = document.getElementById("__demo_titlecard");
      if (el) {
        el.style.opacity = "0";
        setTimeout(() => el.remove(), 400);
      }
    })
    .catch(() => {});
  await page.waitForTimeout(450);
}

/** Convenience: set a caption, optionally run an action, then hold the beat. */
export async function step(
  page: Page,
  cap: { title: string; subtitle?: string },
  action?: () => Promise<void>,
  ms: number = BEAT,
): Promise<void> {
  await caption(page, cap.title, cap.subtitle ?? "");
  if (action) await action();
  await beat(page, ms);
}

/** Navigate + small settle so the page is painted before the next beat. */
export async function visit(page: Page, path: string, settleMs = 1200): Promise<void> {
  await page.goto(`${BASE}${path}`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(settleMs);
}

/** Draw a temporary highlight ring around an element (centered, glowing). */
export async function highlight(page: Page, locator: Locator): Promise<void> {
  await locator
    .evaluate((el) => {
      const prev = (el as HTMLElement).style.cssText;
      (el as HTMLElement).dataset.__demoPrev = prev;
      (el as HTMLElement).style.outline = "3px solid #60a5fa";
      (el as HTMLElement).style.outlineOffset = "3px";
      (el as HTMLElement).style.borderRadius = (el as HTMLElement).style.borderRadius || "8px";
      (el as HTMLElement).style.boxShadow = "0 0 0 6px rgba(96,165,250,.25)";
      (el as HTMLElement).style.transition = "box-shadow .3s ease, outline .3s ease";
    })
    .catch(() => {});
}

/** Remove a previously-applied highlight ring. */
export async function unhighlight(page: Page, locator: Locator): Promise<void> {
  await locator
    .evaluate((el) => {
      const h = el as HTMLElement;
      h.style.outline = "";
      h.style.boxShadow = "";
    })
    .catch(() => {});
}

/**
 * Bring a target on-screen and PROVE it: scroll it to center, set the caption,
 * ASSERT it is actually in the viewport (the recording fails if it isn't — this
 * enforces "what we're showing is scrolled to and visible"), highlight it, hold
 * the beat, then drop the highlight.
 *
 * `target` may be a Locator or a string (resolved as getByText, first match).
 */
export async function reveal(
  page: Page,
  target: Locator | string,
  title: string,
  subtitle = "",
  opts: { ms?: number; ring?: boolean; exact?: boolean } = {},
): Promise<void> {
  const loc =
    typeof target === "string"
      ? page.getByText(target, { exact: opts.exact ?? false }).first()
      : target;
  await loc.scrollIntoViewIfNeeded({ timeout: 12_000 }).catch(() => {});
  // Center it in the viewport for a clean shot.
  await loc
    .evaluate((el) => el.scrollIntoView({ block: "center", inline: "center", behavior: "instant" as ScrollBehavior }))
    .catch(() => {});
  await page.waitForTimeout(350);
  await caption(page, title, subtitle);
  // Enforce visibility: the take is only valid if the target is on screen.
  await expect(loc).toBeInViewport({ ratio: 0.2, timeout: 12_000 });
  if (opts.ring !== false) await highlight(page, loc);
  await beat(page, opts.ms ?? BEAT);
  if (opts.ring !== false) await unhighlight(page, loc);
}

/** Like reveal() but for an action target you also click after showing it. */
export async function revealClick(
  page: Page,
  target: Locator | string,
  title: string,
  subtitle = "",
  opts: { ms?: number; settleMs?: number } = {},
): Promise<void> {
  const loc = typeof target === "string" ? page.getByText(target).first() : target;
  await reveal(page, loc, title, subtitle, { ms: opts.ms ?? 1800 });
  await loc.click().catch(() => {});
  await page.waitForTimeout(opts.settleMs ?? 1400);
}

/* ── Off-camera seeding helpers (shared by the v2 segments) ────────────────── */

export const PYTHON = "/home/ubuntu/testlogon/.venv/bin/python3";

/**
 * Run an inline Python snippet against the local stack. The harness, prepended
 * to every body, sources `.env.local` into os.environ (so AWS creds / DDB / KMS
 * endpoints resolve exactly like the backend), puts the repo root on sys.path
 * (so `from app...` imports work — e.g. kms_encrypt), and exposes a ready DDB
 * resource as `ddb`. Returns captured stdout (use `print(...)` to surface ids).
 *
 * CONSTRAINT: the body is embedded inside a double-quoted shell `-c "..."`, so
 * use ONLY single quotes inside the Python body and avoid f-strings/`$` (build
 * strings with concatenation), mirroring the proven seg07 helper.
 */
export function py(body: string): string {
  return execSync(
    `${PYTHON} -c "
import os, sys
sys.path.insert(0, '/home/ubuntu/testlogon')
from pathlib import Path
env = Path('/home/ubuntu/testlogon/.env.local')
if env.exists():
    for line in env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())
import boto3
ddb = boto3.resource('dynamodb', endpoint_url=os.environ.get('DDB_ENDPOINT_URL','http://localhost:8001'), region_name='us-east-1', aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID','test'), aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY','test'))
${body}
"`,
    { cwd: "/home/ubuntu/testlogon", timeout: 30_000 },
  )
    .toString()
    .trim();
}

/**
 * Re-auth the SAME browser context as a different seeded identity: clear cookies,
 * add the target's cookies, and inject the auth-store (role-aware token) so the
 * next navigation renders as that user. Must be followed by a page.goto().
 */
export async function reauth(page: Page, key: string): Promise<SessionData> {
  const sess = loadSessions()[key];
  if (!sess) throw new Error(`No seeded session for identity "${key}"`);
  await page.context().clearCookies();
  await page.context().addCookies(sess.cookies);
  await page.addInitScript(
    ({ uid, token }: { uid: string; token: string }) => {
      const state = { userId: uid, accessToken: token, isAuthenticated: true };
      localStorage.setItem("auth-store", JSON.stringify({ state, version: 0 }));
    },
    { uid: sess.user_sub, token: sess.access_token },
  );
  return sess;
}
