export function reportNewsfeedRendererEvent(reason: "unsupported_format" | "render_exception", bodyFormat?: string, surface: "post" | "comment" | "unknown" = "unknown") {
  const payload = JSON.stringify({ reason, body_format: bodyFormat, surface });
  const url = "/telemetry/content-render";
  try {
    if (typeof navigator !== "undefined" && typeof navigator.sendBeacon === "function") {
      navigator.sendBeacon(url, new Blob([payload], { type: "application/json" }));
      return;
    }
  } catch {
    // no-op
  }
  void fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: payload,
  }).catch(() => undefined);
}
