import { describe, expect, it, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import FilesPage from "../FilesPage";

const listFiles = vi.fn();
const searchFiles = vi.fn();
const searchText = vi.fn();
const createFolder = vi.fn();
const uploadFile = vi.fn();
const deleteFile = vi.fn();
const deleteFolder = vi.fn();
const renameFile = vi.fn();
const renameFolder = vi.fn();
const moveFile = vi.fn();
const uploadZip = vi.fn();
const fsPresignUpload = vi.fn();
const completeUpload = vi.fn();
const emitFileCryptoTelemetry = vi.fn();
const getSharedFileInfo = vi.fn();
const getUsageSummary = vi.fn();
const listMounts = vi.fn();
const rotateICloudMount = vi.fn();
const revokeICloudMount = vi.fn();
const sharedPreviewUrl = vi.fn();
const initiateICloudMount = vi.fn();
const verifyICloudMount = vi.fn();

vi.mock("@/api/endpoints/files", () => ({
  listFiles: (...args: unknown[]) => listFiles(...args),
  searchFiles: (...args: unknown[]) => searchFiles(...args),
  searchText: (...args: unknown[]) => searchText(...args),
  createFolder: (...args: unknown[]) => createFolder(...args),
  uploadFile: (...args: unknown[]) => uploadFile(...args),
  deleteFile: (...args: unknown[]) => deleteFile(...args),
  deleteFolder: (...args: unknown[]) => deleteFolder(...args),
  renameFile: (...args: unknown[]) => renameFile(...args),
  renameFolder: (...args: unknown[]) => renameFolder(...args),
  moveFile: (...args: unknown[]) => moveFile(...args),
  uploadZip: (...args: unknown[]) => uploadZip(...args),
  fsPresignUpload: (...args: unknown[]) => fsPresignUpload(...args),
  completeUpload: (...args: unknown[]) => completeUpload(...args),
  emitFileCryptoTelemetry: (...args: unknown[]) => emitFileCryptoTelemetry(...args),
  getSharedFileInfo: (...args: unknown[]) => getSharedFileInfo(...args),
  getUsageSummary: (...args: unknown[]) => getUsageSummary(...args),
  listMounts: (...args: unknown[]) => listMounts(...args),
  rotateICloudMount: (...args: unknown[]) => rotateICloudMount(...args),
  revokeICloudMount: (...args: unknown[]) => revokeICloudMount(...args),
  sharedPreviewUrl: (...args: unknown[]) => sharedPreviewUrl(...args),
  initiateICloudMount: (...args: unknown[]) => initiateICloudMount(...args),
  verifyICloudMount: (...args: unknown[]) => verifyICloudMount(...args),
}));

vi.mock("../FileTable", () => ({
  FileTable: ({ data, onNavigate }: { data: Array<{ type: string; path: string; name: string }>; onNavigate: (f: any) => void }) => (
    <div data-testid="file-table">
      {(data ?? [])
        .filter((row) => row.type === "folder")
        .map((row) => (
          <button key={row.path} data-testid={`navigate-${row.path}`} onClick={() => onNavigate(row)}>
            {row.name}
          </button>
        ))}
    </div>
  ),
}));
vi.mock("../UploadZone", () => ({ UploadZone: ({ children }: { children: unknown }) => <div>{children as any}</div> }));
vi.mock("../SharedWithMe", () => ({ SharedWithMe: () => <div /> }));
vi.mock("../ShareDialog", () => ({ ShareDialog: () => null }));
vi.mock("../BulkActions", () => ({ BulkActions: () => null }));
vi.mock("../MoveDialog", () => ({ MoveDialog: () => null }));

const renderPage = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <FilesPage />
      </QueryClientProvider>
    </MemoryRouter>,
  );
};

describe("FilesPage iCloud onboarding wizard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listFiles.mockResolvedValue({ path: "/", items: [] });
    searchFiles.mockResolvedValue({ results: [] });
    searchText.mockResolvedValue({ results: [] });
    listMounts.mockResolvedValue([]);
    getUsageSummary.mockResolvedValue({
      period_id: "2026-01",
      upload: { used_bytes: 0, limit_bytes: 100, percent_used: 0 },
      download: { used_bytes: 0, limit_bytes: 100, percent_used: 0 },
      storage: { used_bytes: 0, limit_bytes: 100, percent_used: 0 },
    });
  });

  it("supports initiate + verify with MFA challenge and success", async () => {
    initiateICloudMount.mockResolvedValue({
      onboarding_session_id: "filemgr_mount_onboard#abc",
      mount_id: "m1",
      status: "pending",
      next_action: "verify",
      expires_at: "2026-01-01T00:00:00+00:00",
    });
    verifyICloudMount
      .mockResolvedValueOnce({
        onboarding_session_id: "filemgr_mount_onboard#abc",
        mount_id: "m1",
        status: "pending",
        next_action: "mfa_required",
        outcome: "mfa_required",
      })
      .mockResolvedValueOnce({
        onboarding_session_id: "filemgr_mount_onboard#abc",
        mount_id: "m1",
        status: "active",
        next_action: "none",
        outcome: "active",
      });

    renderPage();

    fireEvent.click(await screen.findByTestId("connect-icloud-button"));
    await screen.findByTestId("icloud-onboarding-wizard");

    fireEvent.change(screen.getByLabelText("Apple ID"), { target: { value: "user@example.com" } });
    fireEvent.change(screen.getByLabelText("Credential"), { target: { value: "secret-token" } });
    fireEvent.change(screen.getByLabelText("Device label (optional)"), { target: { value: "My MacBook" } });

    fireEvent.click(screen.getByRole("button", { name: /start onboarding/i }));

    await waitFor(() => expect(initiateICloudMount).toHaveBeenCalled());
    expect(initiateICloudMount).toHaveBeenCalledWith(
      expect.objectContaining({
        mount_path: "/icloud/",
        apple_id: "user@example.com",
        auth_value: "secret-token",
      }),
    );

    await screen.findByLabelText("MFA / challenge code");
    fireEvent.click(screen.getByRole("button", { name: /verify & connect/i }));

    await screen.findByText(/multi-factor authentication required/i);

    fireEvent.change(screen.getByLabelText("MFA / challenge code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: /verify & connect/i }));

    await screen.findByTestId("icloud-onboarding-success");
    expect(verifyICloudMount).toHaveBeenCalledTimes(2);
    expect(verifyICloudMount).toHaveBeenLastCalledWith({
      onboarding_session_id: "filemgr_mount_onboard#abc",
      mfa_code: "123456",
    });
  });

  it("shows auth failure state", async () => {
    initiateICloudMount.mockResolvedValue({
      onboarding_session_id: "filemgr_mount_onboard#abc",
      mount_id: "m1",
      status: "pending",
      next_action: "verify",
      expires_at: "2026-01-01T00:00:00+00:00",
    });
    verifyICloudMount.mockResolvedValue({
      onboarding_session_id: "filemgr_mount_onboard#abc",
      mount_id: "m1",
      status: "failed",
      next_action: "reconnect",
      outcome: "auth_failed",
    });

    renderPage();
    fireEvent.click(await screen.findByTestId("connect-icloud-button"));

    fireEvent.change(screen.getByLabelText("Apple ID"), { target: { value: "user@example.com" } });
    fireEvent.change(screen.getByLabelText("Credential"), { target: { value: "secret-token" } });
    fireEvent.click(screen.getByRole("button", { name: /start onboarding/i }));

    await screen.findByLabelText("MFA / challenge code");
    fireEvent.click(screen.getByRole("button", { name: /verify & connect/i }));

    await waitFor(() => expect(verifyICloudMount).toHaveBeenCalled());
    expect(screen.queryByTestId("icloud-onboarding-success")).not.toBeInTheDocument();
  });

  it("does not surface sensitive credential content in initiate errors", async () => {
    initiateICloudMount.mockRejectedValue(new Error("secret manager error: token=secret-token"));

    renderPage();
    fireEvent.click(await screen.findByTestId("connect-icloud-button"));

    fireEvent.change(screen.getByLabelText("Apple ID"), { target: { value: "user@example.com" } });
    fireEvent.change(screen.getByLabelText("Credential"), { target: { value: "secret-token" } });
    fireEvent.click(screen.getByRole("button", { name: /start onboarding/i }));

    const err = await screen.findByTestId("icloud-onboarding-error");
    expect(err.textContent?.toLowerCase()).toContain("failed to initiate icloud onboarding");
    expect(err.textContent).not.toContain("secret-token");
  });

  it("supports re-auth UX from mount panel after auth expiry", async () => {
    listMounts.mockResolvedValueOnce([
      {
        mount_id: "m-reauth",
        provider: "icloud",
        mount_path: "/icloud-work/",
        status: "reauth_required",
        can_rotate: true,
        can_reconnect: true,
        can_disconnect: true,
      },
    ]);
    initiateICloudMount.mockResolvedValue({
      onboarding_session_id: "filemgr_mount_onboard#reauth",
      mount_id: "m-reauth",
      status: "pending",
      next_action: "verify",
      expires_at: "2026-01-01T00:00:00+00:00",
    });
    verifyICloudMount.mockResolvedValue({
      onboarding_session_id: "filemgr_mount_onboard#reauth",
      mount_id: "m-reauth",
      status: "active",
      next_action: "none",
      outcome: "active",
    });

    renderPage();

    fireEvent.click(await screen.findByTestId("mount-reconnect-m-reauth"));
    expect(await screen.findByTestId("icloud-onboarding-wizard")).toBeInTheDocument();
    expect(screen.getByLabelText("Mount path")).toHaveValue("/icloud-work/");

    fireEvent.change(screen.getByLabelText("Apple ID"), { target: { value: "user@example.com" } });
    fireEvent.change(screen.getByLabelText("Credential"), { target: { value: "renewed-token" } });
    fireEvent.click(screen.getByRole("button", { name: /start onboarding/i }));
    await waitFor(() => expect(initiateICloudMount).toHaveBeenCalled());

    fireEvent.click(screen.getByRole("button", { name: /verify & connect/i }));
    expect(await screen.findByTestId("icloud-onboarding-success")).toBeInTheDocument();
    expect(verifyICloudMount).toHaveBeenCalledWith({ onboarding_session_id: "filemgr_mount_onboard#reauth" });
  });

  it("renders mount status badges and mount management actions", async () => {
    listMounts.mockResolvedValue([
      {
        mount_id: "m-active",
        provider: "icloud",
        mount_path: "/icloud/",
        status: "active",
        can_rotate: true,
        can_reconnect: false,
        can_disconnect: true,
      },
      {
        mount_id: "m-reauth",
        provider: "icloud",
        mount_path: "/icloud-work/",
        status: "reauth_required",
        can_rotate: true,
        can_reconnect: true,
        can_disconnect: true,
      },
      {
        mount_id: "m-revoked",
        provider: "icloud",
        mount_path: "/icloud-old/",
        status: "revoked",
        can_rotate: false,
        can_reconnect: true,
        can_disconnect: false,
      },
      {
        mount_id: "m-degraded",
        provider: "icloud",
        mount_path: "/icloud-slow/",
        status: "degraded",
        can_rotate: true,
        can_reconnect: true,
        can_disconnect: true,
      },
    ]);
    revokeICloudMount.mockResolvedValue({ mount_id: "m-active", status: "revoked", sessions_cleared: 1 });
    rotateICloudMount.mockResolvedValue({ mount_id: "m-active", secret_ref: "sec", status: "active" });

    renderPage();

    expect(await screen.findByTestId("mount-management-panel")).toBeInTheDocument();
    expect(await screen.findByText("active")).toBeInTheDocument();
    expect(await screen.findByText("degraded")).toBeInTheDocument();
    expect(await screen.findByText("re-auth required")).toBeInTheDocument();
    expect(await screen.findByText("revoked")).toBeInTheDocument();

    expect(screen.queryByTestId("mount-rotate-m-revoked")).not.toBeInTheDocument();
    expect(screen.getByTestId("mount-reconnect-m-revoked")).toBeInTheDocument();

    fireEvent.click(screen.getByTestId("mount-rotate-m-active"));
    fireEvent.change(screen.getByLabelText("Credential"), { target: { value: "new-secret" } });
    fireEvent.click(screen.getByTestId("mount-rotate-submit-m-active"));
    await waitFor(() => expect(rotateICloudMount).toHaveBeenCalledWith(expect.objectContaining({ mount_id: "m-active" })));

    fireEvent.click(screen.getByTestId("mount-disconnect-m-active"));
    await waitFor(() => expect(revokeICloudMount).toHaveBeenCalledWith({ mount_id: "m-active" }));

    fireEvent.click(screen.getByTestId("mount-reconnect-m-revoked"));
    expect(await screen.findByTestId("icloud-onboarding-wizard")).toBeInTheDocument();
    expect(screen.getByLabelText("Mount path")).toHaveValue("/icloud-old/");
  });

});
