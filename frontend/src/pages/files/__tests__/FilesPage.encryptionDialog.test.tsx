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
const getUsageSummary = vi.fn();

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
  getUsageSummary: (...args: unknown[]) => getUsageSummary(...args),
}));

vi.mock("../FileTable", () => ({ FileTable: () => <div data-testid="file-table" /> }));
vi.mock("../UploadZone", () => ({ UploadZone: ({ children }: { children: unknown }) => <div>{children as any}</div> }));
vi.mock("../SharedWithMe", () => ({ SharedWithMe: () => <div /> }));
vi.mock("../ShareDialog", () => ({ ShareDialog: () => null }));
vi.mock("../BulkActions", () => ({ BulkActions: () => null }));
vi.mock("../MoveDialog", () => ({ MoveDialog: () => null }));

describe("FilesPage encryption password dialog", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listFiles.mockResolvedValue({ path: "/", items: [] });
    searchFiles.mockResolvedValue({ results: [] });
    searchText.mockResolvedValue({ results: [] });
    uploadFile.mockResolvedValue({ ok: true, path: "/a.txt", size: 1 });
    getUsageSummary.mockResolvedValue({
      period_id: "2026-01",
      upload: { used_bytes: 0, limit_bytes: 100, percent_used: 0 },
      download: { used_bytes: 0, limit_bytes: 100, percent_used: 0 },
      storage: { used_bytes: 0, limit_bytes: 100, percent_used: 0 },
    });
  });

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

  it("enforces mismatch/cancel/retry dialog behavior", async () => {
    const { container } = renderPage();

    const encryptToggle = await screen.findByRole("checkbox", { name: /encrypt uploads/i });
    fireEvent.click(encryptToggle);

    const fileInput = container.querySelector('input[type="file"][multiple]') as HTMLInputElement;
    const file = new File(["abc"], "a.txt", { type: "text/plain" });

    fireEvent.change(fileInput, { target: { files: [file] } });

    await screen.findByText("Set encryption password");

    const password = screen.getByLabelText("Password");
    const confirm = screen.getByLabelText("Confirm password");
    fireEvent.change(password, { target: { value: "Strong!Pass123" } });
    fireEvent.change(confirm, { target: { value: "Different!Pass123" } });

    const continueBtn = screen.getByRole("button", { name: "Continue" });
    expect(continueBtn).toBeDisabled();

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByText("Set encryption password")).not.toBeInTheDocument());
    expect(uploadFile).not.toHaveBeenCalled();

    fireEvent.change(fileInput, { target: { files: [file] } });
    await screen.findByText("Set encryption password");
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "Strong!Pass123" } });
    fireEvent.change(screen.getByLabelText("Confirm password"), { target: { value: "Strong!Pass123" } });

    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    await waitFor(() => expect(uploadFile).toHaveBeenCalled());
  });
});
