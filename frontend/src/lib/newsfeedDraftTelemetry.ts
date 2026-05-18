type DraftLifecycleEvent =
  | "save_success"
  | "save_fail"
  | "load_success"
  | "load_fail"
  | "delete_success"
  | "delete_fail"
  | "publish_from_draft";

type DraftLifecycleOutcome = "success" | "fail";

export function reportDraftLifecycleEvent(
  event: DraftLifecycleEvent,
  outcome: DraftLifecycleOutcome,
  reasonCode?: string,
): void {
  const payload = JSON.stringify({
    event,
    outcome,
    reason_code: reasonCode,
    surface: "composer",
  });
  const url = "/telemetry/draft-lifecycle";
  try {
    if (typeof navigator !== "undefined" && typeof navigator.sendBeacon === "function") {
      navigator.sendBeacon(url, new Blob([payload], { type: "application/json" }));
      return;
    }
  } catch {
    // no-op fallback to fetch below
  }
  void fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: payload,
    credentials: "include",
    keepalive: true,
  }).catch(() => {});
}
