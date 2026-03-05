import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import RemoteDesktopPage from "@/pages/remote/RemoteDesktopPage";
import { ApiError } from "@/api/client";

const createVncSession = vi.fn();
const deleteVncSession = vi.fn();
const getVncTransferFallback = vi.fn();
const navigateMock = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

vi.mock("@/api/endpoints/vnc", () => ({
  createVncSession: (...args: unknown[]) => createVncSession(...args),
  deleteVncSession: (...args: unknown[]) => deleteVncSession(...args),
  getVncTransferFallback: (...args: unknown[]) => getVncTransferFallback(...args),
}));

let lastRfbInstance: MockRfb | null = null;

class MockRfb {
  public scaleViewport = false;
  public viewOnly = false;
  private handlers: Record<string, EventListener[]> = {};
  disconnect = vi.fn(() => this.emit("disconnect"));
  sendCtrlAltDel = vi.fn();
  clipboardPasteFrom = vi.fn();

  constructor(_target: Element, _url: string, _options: Record<string, unknown> = {}) {
    lastRfbInstance = this;
  }

  addEventListener(event: string, handler: EventListener) {
    this.handlers[event] = this.handlers[event] || [];
    this.handlers[event]!.push(handler);
  }

  emit(event: string) {
    for (const h of this.handlers[event] || []) h(new Event(event));
  }
}

describe("RemoteDesktopPage", () => {
  beforeEach(() => {
    createVncSession.mockReset();
    deleteVncSession.mockReset();
    getVncTransferFallback.mockReset();
    navigateMock.mockReset();
    localStorage.clear();
    lastRfbInstance = null;
    if (!document.exitFullscreen) {
      Object.defineProperty(document, "exitFullscreen", { value: vi.fn(), configurable: true });
    }
    (window as Window & { __TEST_RFB__?: typeof MockRfb }).__TEST_RFB__ = MockRfb;
    Object.defineProperty(navigator, "clipboard", {
      value: {
        readText: vi.fn().mockResolvedValue("local clipboard"),
        writeText: vi.fn().mockResolvedValue(undefined),
      },
      configurable: true,
    });
  });

  it("blocks invalid form submit with inline validation", async () => {
    render(<MemoryRouter><RemoteDesktopPage /></MemoryRouter>);
    fireEvent.click(screen.getByRole("button", { name: /connect viewer/i }));
    expect(await screen.findByText(/^Target ID is required\.$/i)).toBeInTheDocument();
    expect(createVncSession).not.toHaveBeenCalled();
  });

  it("connects viewer and updates state to connected", async () => {
    createVncSession.mockResolvedValue({
      session_id: "vnc_123", ws_url: "ws://localhost:6080/websockify", connect_params: { token: "abc" }, expires_at: 1_900_000_000,
      capabilities: { clipboard: true, file_transfer: false, drag_drop_upload: false },
    });
    render(<MemoryRouter><RemoteDesktopPage /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText(/target id/i), { target: { value: "demo" } });
    fireEvent.click(screen.getByRole("button", { name: /connect viewer/i }));
    await waitFor(() => expect(createVncSession).toHaveBeenCalledWith({ target_id: "demo" }));
    await act(async () => { lastRfbInstance?.emit("connect"); });
    expect(screen.getByTestId("connection-state-badge")).toHaveTextContent("connected");
  });

  it("supports CAD and disconnect controls", async () => {
    createVncSession.mockResolvedValue({
      session_id: "vnc_456", ws_url: "ws://localhost:6080/websockify", connect_params: { token: "abc" }, expires_at: 1_900_000_000,
      capabilities: { clipboard: true, file_transfer: false, drag_drop_upload: false },
    });
    deleteVncSession.mockResolvedValue({ session_id: "vnc_456", status: "closed", closed_at: 1_900_000_010 });
    render(<MemoryRouter><RemoteDesktopPage /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText(/target id/i), { target: { value: "demo" } });
    fireEvent.click(screen.getByRole("button", { name: /connect viewer/i }));
    await waitFor(() => expect(lastRfbInstance).not.toBeNull());
    await act(async () => { lastRfbInstance?.emit("connect"); });
    fireEvent.click(screen.getByRole("button", { name: /ctrl\+alt\+del/i }));
    expect(lastRfbInstance?.sendCtrlAltDel).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: /^disconnect$/i }));
    await waitFor(() => expect(deleteVncSession).toHaveBeenCalledWith("vnc_456"));
  });

  it("maps backend ADR error code to clear message and failed state", async () => {
    createVncSession.mockRejectedValue(new ApiError(404, "Not found", { detail: { error: { code: "VNC_TARGET_NOT_FOUND" } } }));
    render(<MemoryRouter><RemoteDesktopPage /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText(/target id/i), { target: { value: "missing-target" } });
    fireEvent.click(screen.getByRole("button", { name: /connect viewer/i }));
    expect(await screen.findByTestId("vnc-form-status")).toHaveTextContent(/VNC_TARGET_NOT_FOUND/);
  });

  it("shows reconnect CTA and applies retry backoff for transient errors", async () => {
    createVncSession.mockRejectedValue(new ApiError(504, "Timeout", { detail: { error: { code: "VNC_BRIDGE_TIMEOUT" } } }));
    render(<MemoryRouter><RemoteDesktopPage /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText(/target id/i), { target: { value: "demo" } });
    fireEvent.click(screen.getByRole("button", { name: /connect viewer/i }));
    const retryButton = await screen.findByRole("button", { name: /retry \/ reconnect/i });
    expect(retryButton).toBeDisabled();
  });

  it("shows session expiry banner and redirects to login for expired session errors", async () => {
    createVncSession.mockRejectedValue(new ApiError(401, "Expired", { detail: { error: { code: "VNC_TOKEN_EXPIRED" } } }));
    render(<MemoryRouter><RemoteDesktopPage /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText(/target id/i), { target: { value: "demo" } });
    fireEvent.click(screen.getByRole("button", { name: /connect viewer/i }));
    expect(await screen.findByTestId("vnc-expiry-banner")).toBeInTheDocument();
    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/login", { replace: true }), { timeout: 3200 });
  });

  it("sends clipboard text to remote when capability and viewer support are available", async () => {
    createVncSession.mockResolvedValue({
      session_id: "vnc_clip_1", ws_url: "ws://localhost:6080/websockify", connect_params: { token: "abc" }, expires_at: 1_900_000_000,
      capabilities: { clipboard: true, file_transfer: false, drag_drop_upload: false },
    });
    render(<MemoryRouter><RemoteDesktopPage /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText(/target id/i), { target: { value: "demo" } });
    fireEvent.click(screen.getByRole("button", { name: /connect viewer/i }));
    await waitFor(() => expect(lastRfbInstance).not.toBeNull());
    await act(async () => { lastRfbInstance?.emit("connect"); });
    fireEvent.change(screen.getByTestId("vnc-clipboard-input"), { target: { value: "hello remote" } });
    fireEvent.click(screen.getByRole("button", { name: /send to remote/i }));
    expect(lastRfbInstance?.clipboardPasteFrom).toHaveBeenCalledWith("hello remote");
  });

  it("indicates unsupported clipboard flows when capability is disabled", async () => {
    createVncSession.mockResolvedValue({
      session_id: "vnc_clip_3", ws_url: "ws://localhost:6080/websockify", connect_params: { token: "abc" }, expires_at: 1_900_000_000,
      capabilities: { clipboard: false, file_transfer: false, drag_drop_upload: false },
    });
    render(<MemoryRouter><RemoteDesktopPage /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText(/target id/i), { target: { value: "demo" } });
    fireEvent.click(screen.getByRole("button", { name: /connect viewer/i }));
    await waitFor(() => expect(lastRfbInstance).not.toBeNull());
    await act(async () => { lastRfbInstance?.emit("connect"); });
    fireEvent.click(screen.getByRole("button", { name: /read local clipboard/i }));
    expect(await screen.findByTestId("vnc-clipboard-status")).toHaveTextContent(/disabled by server capability/i);
  });

  it("shows transfer unsupported message when file_transfer capability is false", async () => {
    createVncSession.mockResolvedValue({
      session_id: "vnc_transfer_1", ws_url: "ws://localhost:6080/websockify", connect_params: { token: "abc" }, expires_at: 1_900_000_000,
      capabilities: { clipboard: true, file_transfer: false, drag_drop_upload: false },
    });
    render(<MemoryRouter><RemoteDesktopPage /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText(/target id/i), { target: { value: "demo" } });
    fireEvent.click(screen.getByRole("button", { name: /connect viewer/i }));
    await waitFor(() => expect(lastRfbInstance).not.toBeNull());
    await act(async () => { lastRfbInstance?.emit("connect"); });
    expect(await screen.findByTestId("vnc-transfer-unsupported")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /upload files/i })).not.toBeInTheDocument();
  });

  it("shows upload controls and drag-drop disabled message when drag_drop_upload is false", async () => {
    createVncSession.mockResolvedValue({
      session_id: "vnc_transfer_2", ws_url: "ws://localhost:6080/websockify", connect_params: { token: "abc" }, expires_at: 1_900_000_000,
      capabilities: { clipboard: true, file_transfer: true, drag_drop_upload: false },
    });
    render(<MemoryRouter><RemoteDesktopPage /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText(/target id/i), { target: { value: "demo" } });
    fireEvent.click(screen.getByRole("button", { name: /connect viewer/i }));
    await waitFor(() => expect(lastRfbInstance).not.toBeNull());
    await act(async () => { lastRfbInstance?.emit("connect"); });
    expect(await screen.findByRole("button", { name: /upload files/i })).toBeInTheDocument();
    expect(screen.getByTestId("vnc-drag-drop-zone")).toHaveTextContent(/disabled for this session/i);
  });

  it("surfaces upload failure with retry when transfer prerequisites are not met", async () => {
    createVncSession.mockResolvedValue({
      session_id: "vnc_transfer_3", ws_url: "ws://localhost:6080/websockify", connect_params: { token: "abc" }, expires_at: 1_900_000_000,
      capabilities: { clipboard: true, file_transfer: true, drag_drop_upload: true },
    });
    render(<MemoryRouter><RemoteDesktopPage /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText(/target id/i), { target: { value: "demo" } });
    fireEvent.click(screen.getByRole("button", { name: /connect viewer/i }));
    await waitFor(() => expect(lastRfbInstance).not.toBeNull());
    await act(async () => { lastRfbInstance?.emit("connect"); lastRfbInstance?.emit("disconnect"); });

    const input = screen.getByTestId("vnc-transfer-input") as HTMLInputElement;
    const file = new File(["hello"], "notes.txt", { type: "text/plain" });
    fireEvent.change(input, { target: { files: [file] } });
    expect(await screen.findByText(/notes\.txt/i)).toBeInTheDocument();
    expect(await screen.findByText(/connect the vnc session before transferring files/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /retry upload/i })).toBeInTheDocument();
  });

  it("requests and renders fallback transfer method when native transfer is unavailable", async () => {
    createVncSession.mockResolvedValue({
      session_id: "vnc_fallback_1", ws_url: "ws://localhost:6080/websockify", connect_params: { token: "abc" }, expires_at: 1_900_000_000,
      capabilities: { clipboard: true, file_transfer: false, drag_drop_upload: false },
    });
    getVncTransferFallback.mockResolvedValue({
      session_id: "vnc_fallback_1",
      method: "object_upload_link",
      label: "Secure Upload Link",
      instructions: "Upload artifacts via link and fetch on remote host.",
      url: "https://uploads.example.internal/vnc",
      expires_at: 1_900_000_300,
    });

    render(<MemoryRouter><RemoteDesktopPage /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText(/target id/i), { target: { value: "demo" } });
    fireEvent.click(screen.getByRole("button", { name: /connect viewer/i }));
    await waitFor(() => expect(lastRfbInstance).not.toBeNull());
    await act(async () => { lastRfbInstance?.emit("connect"); });

    fireEvent.click(screen.getByRole("button", { name: /get fallback transfer method/i }));
    await waitFor(() => expect(getVncTransferFallback).toHaveBeenCalledWith("vnc_fallback_1"));
    expect(await screen.findByTestId("vnc-fallback-transfer-panel")).toHaveTextContent(/secure upload link/i);
  });

  it("shows timeout warning and terminates session when policy window elapses", async () => {
  createVncSession.mockResolvedValue({
    session_id: "vnc_timeout_1",
    ws_url: "ws://localhost:6080/websockify",
    connect_params: { token: "abc" },
    created_at: Math.floor(Date.now() / 1000),
    expires_at: 1_900_000_000,
    capabilities: { clipboard: true, file_transfer: false, drag_drop_upload: false },
    timeout_policy: { idle_timeout_seconds: 6, max_session_duration_seconds: 120, warning_seconds: 4 },
  });
  deleteVncSession.mockResolvedValue({ session_id: "vnc_timeout_1", status: "closed", closed_at: 1_900_000_010 });

  render(<MemoryRouter><RemoteDesktopPage /></MemoryRouter>);
  fireEvent.change(screen.getByLabelText(/target id/i), { target: { value: "demo" } });
  fireEvent.click(screen.getByRole("button", { name: /connect viewer/i }));
  await waitFor(() => expect(lastRfbInstance).not.toBeNull());
  await act(async () => { lastRfbInstance?.emit("connect"); });

  await waitFor(() => expect(screen.queryByTestId("vnc-timeout-warning")).toBeInTheDocument(), { timeout: 4000 });
  await waitFor(() => expect(screen.queryByTestId("vnc-expiry-banner")).toBeInTheDocument(), { timeout: 8000 });
  await waitFor(() => expect(deleteVncSession).toHaveBeenCalledWith("vnc_timeout_1"), { timeout: 8000 });
}, 12000);

});
