import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/api/client";
import { createVncSession, deleteVncSession, getVncTransferFallback } from "@/api/endpoints/vnc";

describe("vnc endpoints", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("normalizes missing/nullable capabilities to deterministic booleans", async () => {
    vi.spyOn(api, "post").mockResolvedValue({
      session_id: "vnc_1",
      ws_url: "ws://localhost:6080/websockify",
      connect_params: { token: "abc" },
      created_at: 1899999700,
      expires_at: 1900000000,
      capabilities: {
        clipboard: true,
        file_transfer: null,
      },
      timeout_policy: {
        idle_timeout_seconds: 120,
        max_session_duration_seconds: 900,
        warning_seconds: 30,
      },
    } as never);

    const resp = await createVncSession({ target_id: "demo" });

    expect(resp.capabilities).toEqual({
      clipboard: true,
      file_transfer: false,
      drag_drop_upload: false,
    });
    expect(resp.timeout_policy).toEqual({
      idle_timeout_seconds: 120,
      max_session_duration_seconds: 900,
      warning_seconds: 30,
    });
  });

  it("maps delete session route path", async () => {
    const spy = vi.spyOn(api, "del").mockResolvedValue({ session_id: "vnc_1", status: "closed" } as never);

    await deleteVncSession("vnc_1");

    expect(spy).toHaveBeenCalledWith("/api/vnc/session/vnc_1");
  });
  it("maps transfer fallback route path", async () => {
    const spy = vi.spyOn(api, "get").mockResolvedValue({ session_id: "vnc_1", method: "sftp" } as never);

    await getVncTransferFallback("vnc_1");

    expect(spy).toHaveBeenCalledWith("/api/vnc/session/vnc_1/transfer-fallback");
  });

});
