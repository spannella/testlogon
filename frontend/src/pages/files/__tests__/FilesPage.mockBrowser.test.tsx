import { describe, expect, it, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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
const listSftpMounts = vi.fn();
const listMountMockFiles = vi.fn();

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
  listSftpMounts: (...args: unknown[]) => listSftpMounts(...args),
  listMountMockFiles: (...args: unknown[]) => listMountMockFiles(...args),
}));

vi.mock("../FileTable", () => ({ FileTable: () => <div data-testid="file-table" /> }));
vi.mock("../UploadZone", () => ({ UploadZone: ({ children }: { children: unknown }) => <div>{children as any}</div> }));
vi.mock("../SharedWithMe", () => ({ SharedWithMe: () => <div /> }));
vi.mock("../ShareDialog", () => ({ ShareDialog: () => null }));
vi.mock("../BulkActions", () => ({ BulkActions: () => null }));
vi.mock("../MoveDialog", () => ({ MoveDialog: () => null }));

describe("FilesPage TypeScript mock browser", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listFiles.mockResolvedValue({ path: "/", items: [] });
    searchFiles.mockResolvedValue({ results: [] });
    searchText.mockResolvedValue({ results: [] });
    getUsageSummary.mockResolvedValue({
      period_id: "2026-01",
      upload: { used_bytes: 100, limit_bytes: 1000, percent_used: 10 },
      download: { used_bytes: 100, limit_bytes: 1000, percent_used: 10 },
      storage: { used_bytes: 100, limit_bytes: 1000, percent_used: 10 },
    });
    listSftpMounts.mockResolvedValue({ items: [{ id: "m1", owner: "u1", host: "h", port: 22, remote_root: "/", read_only: false, status: "healthy", protocol: "sftp" }] });
    listMountMockFiles.mockResolvedValue({
      mount_id: "m1",
      owner: "u1",
      backend: "mock",
      path: "/",
      filesystem_path: "/tmp/filemgr-sftp-mock/u1/m1",
      items: [
        { name: "folderA", path: "/folderA/", type: "folder", size: 0, modified_at: 100 },
        { name: "b.txt", path: "/b.txt", type: "file", size: 20, modified_at: 200 },
      ],
      limit: 200,
      cursor: null,
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

  it("supports mount select, filter/sort controls, and remediation block", async () => {
    renderPage();
    const user = userEvent.setup();
    await user.click(await screen.findByTestId("open-ts-mock-browser"));

    const mountSelect = await screen.findByLabelText("Mount");
    await user.selectOptions(mountSelect, "m1");

    await waitFor(() => expect(listMountMockFiles).toHaveBeenCalled());
    expect(await screen.findByText("/folderA/")).toBeInTheDocument();

    await user.type(screen.getByPlaceholderText("Filter by name or path"), "b.txt");
    expect(screen.getByText("/b.txt")).toBeInTheDocument();

    // error remediation
    listMountMockFiles.mockRejectedValueOnce({
      status: 404,
      body: { detail: { code: "mock_path_not_found" } },
    });
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(screen.getByTestId("mock-browser-remediation")).toBeInTheDocument());
  });

  it("supports nested folder navigation, breadcrumbs, and pagination load-more", async () => {
    listMountMockFiles
      .mockResolvedValueOnce({
        mount_id: "m1",
        owner: "u1",
        backend: "mock",
        path: "/",
        filesystem_path: "/tmp/filemgr-sftp-mock/u1/m1",
        items: [{ name: "team", path: "/team/", type: "folder", size: 0, modified_at: 100 }],
        limit: 200,
        cursor: null,
      })
      .mockResolvedValueOnce({
        mount_id: "m1",
        owner: "u1",
        backend: "mock",
        path: "/team/",
        filesystem_path: "/tmp/filemgr-sftp-mock/u1/m1/team",
        items: [{ name: "one.txt", path: "/team/one.txt", type: "file", size: 1, modified_at: 100 }],
        limit: 200,
        cursor: "c1",
      })
      .mockResolvedValueOnce({
        mount_id: "m1",
        owner: "u1",
        backend: "mock",
        path: "/team/",
        filesystem_path: "/tmp/filemgr-sftp-mock/u1/m1/team",
        items: [{ name: "two.txt", path: "/team/two.txt", type: "file", size: 1, modified_at: 200 }],
        limit: 200,
        cursor: null,
      })
      .mockResolvedValueOnce({
        mount_id: "m1",
        owner: "u1",
        backend: "mock",
        path: "/",
        filesystem_path: "/tmp/filemgr-sftp-mock/u1/m1",
        items: [{ name: "team", path: "/team/", type: "folder", size: 0, modified_at: 100 }],
        limit: 200,
        cursor: null,
      });

    renderPage();
    const user = userEvent.setup();
    await user.click(await screen.findByTestId("open-ts-mock-browser"));
    await user.selectOptions(await screen.findByLabelText("Mount"), "m1");

    await waitFor(() => expect(screen.getByText("/team/")).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: "Open" }));
    await waitFor(() => expect(screen.getByText("/team/one.txt")).toBeInTheDocument());

    const loadMore = await screen.findByRole("button", { name: "Load more" });
    await user.click(loadMore);
    await waitFor(() => expect(screen.getByText("/team/two.txt")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: "root" }));
    await waitFor(() => expect(screen.getByText("/team/")).toBeInTheDocument());
  });

});
