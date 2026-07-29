/**
 * cpp-aware shopping-cart backdating glue for cart-abandonment.spec.ts.
 *
 * The spec drives the cart-abandonment scan by backdating a cart's
 * last_activity_at (and poking reminder_count / last_reminder_at). Its inline
 * DDB helpers write to Python DDB-Local (:8001) table 'shopping_cart' keyed
 * PK=USER#<email>. cpp stores carts in tlc_shopping_cart on moto (:5005) keyed
 * PK=USER#<JWT sub>, SK=CART#<id>. These wrappers land the SAME row cpp's
 * h_cart_scan reads, via the reset-style seed shim cart_timestamp.py on .82.
 *
 * subs passed here MUST be cpp SUBs (not emails).
 */
import { execFileSync } from "child_process";

const CPP_SSH_HOST = process.env.E2E_CPP_SSH_HOST ?? "sean@192.168.0.82";
const CPP_SSH_KEY =
  process.env.E2E_CPP_SSH_KEY ?? "/home/sean/.ssh/e2e_cpp_seed_ed25519";
const CPP_SHIM_DIR =
  process.env.E2E_CPP_SHIM_DIR ??
  "/home/sean/projects/testlogon-cpp/e2e/seed_shims";

function runCartShim(args: Record<string, unknown>): string {
  const b64 = Buffer.from(JSON.stringify(args), "utf8").toString("base64");
  return execFileSync(
    "ssh",
    [
      "-i", CPP_SSH_KEY,
      "-o", "IdentitiesOnly=yes",
      "-o", "BatchMode=yes",
      "-o", "ConnectTimeout=20",
      "-o", "ControlMaster=auto",
      "-o", `ControlPath=/home/sean/.ssh/cm-cppseed-w${process.env.TEST_WORKER_INDEX || "0"}-%C`,
      "-o", "ControlPersist=180",
      CPP_SSH_HOST,
      `python3 ${CPP_SHIM_DIR}/cart_timestamp.py --b64 ${b64}`,
    ],
    { timeout: 30_000, encoding: "utf8" },
  ).trim();
}

/** SET last_activity_at on cpp's cart row (backdate to force abandonment). */
export function cppCartTimestamp(sub: string, cartId: string, lastActivityAt: number): void {
  const out = runCartShim({ mode: "update", sub, cart_id: cartId, last_activity_at: lastActivityAt });
  if (out !== "ok") throw new Error(`cpp cart timestamp failed: ${out}`);
}

/** SET reminder_count + last_reminder_at on cpp's cart row. */
export function cppCartSetReminder(sub: string, cartId: string, count: number, lastReminderAt: number): void {
  const out = runCartShim({ mode: "set_reminder", sub, cart_id: cartId, reminder_count: count, last_reminder_at: lastReminderAt });
  if (out !== "ok") throw new Error(`cpp cart set_reminder failed: ${out}`);
}

/** GET the raw cpp cart row (mirrors ddbGetCartRaw for the cpp store). */
export function cppCartGetRaw(sub: string, cartId: string): Record<string, unknown> {
  const out = runCartShim({ mode: "get", sub, cart_id: cartId });
  return JSON.parse(out || "{}");
}

/**
 * Delete ALL of the user's cpp cart rows so the abandonment scan starts clean.
 * cpp's moto persists carts across runs (the Python path got a fresh DDB), so
 * without this a scan reminds stale prior-run abandoned carts and breaks
 * "recently active cart is NOT abandoned" style assertions.
 */
export function cppCartClear(sub: string): void {
  runCartShim({ mode: "clear", sub });
}
