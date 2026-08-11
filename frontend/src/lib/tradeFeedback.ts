/**
 * Web-native trade feedback — the browser analog of the Android TradingNotifier.
 *
 * - `vibrate(kind)` uses the Vibration API (Android Chrome supports it; iOS Safari and desktop
 *   simply ignore it — always a safe no-op).
 * - `notify(title, body)` shows a system Notification when the user has granted permission, so a
 *   fill is felt/seen even when the trading tab isn't focused. `ensureNotifyPermission()` requests
 *   permission lazily, once, from a user gesture.
 * All calls are failure-safe (wrapped) and no-op when the API is unavailable.
 */

export type Haptic = "tick" | "success" | "warn" | "error";

const PATTERNS: Record<Haptic, number | number[]> = {
  tick: 10,
  success: [0, 25, 50, 25],
  warn: 30,
  error: [0, 40, 50, 40, 50, 40],
};

export function vibrate(kind: Haptic): void {
  try {
    if (typeof navigator !== "undefined" && typeof navigator.vibrate === "function") {
      navigator.vibrate(PATTERNS[kind]);
    }
  } catch {
    /* ignore */
  }
}

let asked = false;
export function ensureNotifyPermission(): void {
  try {
    if (typeof Notification === "undefined") return;
    if (Notification.permission === "default" && !asked) {
      asked = true;
      void Notification.requestPermission();
    }
  } catch {
    /* ignore */
  }
}

export function notify(title: string, body: string): void {
  try {
    if (typeof Notification === "undefined" || Notification.permission !== "granted") return;
    new Notification(title, { body });
  } catch {
    /* ignore */
  }
}
