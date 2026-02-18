import { describe, expect, it, beforeEach, vi } from "vitest";
import { render, screen } from "@testing-library/react";
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

describe("FilesPage usage widget and banners", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listFiles.mockResolvedValue({ path: "/", items: [] });
    searchFiles.mockResolvedValue({ results: [] });
    searchText.mockResolvedValue({ results: [] });
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

  it("renders compact usage widget", async () => {
    getUsageSummary.mockResolvedValue({
      period_id: "2026-01",
      upload: { used_bytes: 100, limit_bytes: 1000, percent_used: 10 },
      download: { used_bytes: 200, limit_bytes: 1000, percent_used: 20 },
      storage: { used_bytes: 300, limit_bytes: 1000, percent_used: 30 },
    });

    renderPage();
    expect(await screen.findByTestId("files-usage-widget")).toBeInTheDocument();
    expect(await screen.findByText(/Transfer:/i)).toBeInTheDocument();
  });

  it("shows warning banner at high usage", async () => {
    getUsageSummary.mockResolvedValue({
      period_id: "2026-01",
      upload: { used_bytes: 960, limit_bytes: 1000, percent_used: 96 },
      download: { used_bytes: 100, limit_bytes: 1000, percent_used: 10 },
      storage: { used_bytes: 820, limit_bytes: 1000, percent_used: 82 },
    });

    renderPage();
    expect(await screen.findByTestId("usage-warning-banner")).toBeInTheDocument();
    expect(screen.getByText(/Upload 96.0%/i)).toBeInTheDocument();
  });

  it("does not show warning banner below threshold", async () => {
    getUsageSummary.mockResolvedValue({
      period_id: "2026-01",
      upload: { used_bytes: 790, limit_bytes: 1000, percent_used: 79 },
      download: { used_bytes: 100, limit_bytes: 1000, percent_used: 10 },
      storage: { used_bytes: 300, limit_bytes: 1000, percent_used: 30 },
    });

    renderPage();
    expect(await screen.findByTestId("files-usage-widget")).toBeInTheDocument();
    expect(screen.queryByTestId("usage-warning-banner")).not.toBeInTheDocument();
  });

  it("shows warning banner and limit messaging at 80 percent threshold", async () => {
    getUsageSummary.mockResolvedValue({
      period_id: "2026-01",
      upload: { used_bytes: 800, limit_bytes: 1000, percent_used: 80 },
      download: { used_bytes: 100, limit_bytes: 1000, percent_used: 10 },
      storage: { used_bytes: 300, limit_bytes: 1000, percent_used: 30 },
    });

    renderPage();
    expect(await screen.findByTestId("usage-warning-banner")).toBeInTheDocument();
    expect(screen.getByText(/Upload 80.0%/i)).toBeInTheDocument();
  });

});
