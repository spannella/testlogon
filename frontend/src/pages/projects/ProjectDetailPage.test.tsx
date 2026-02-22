import { describe, expect, it, beforeEach, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import ProjectDetailPage from "./ProjectDetailPage";

const getProjectDetail = vi.fn();
const addTrackedFile = vi.fn();
const removeTrackedFile = vi.fn();
const toastSuccess = vi.fn();
const toastError = vi.fn();

vi.mock("@/api/endpoints/projects", () => ({
  getProjectDetail: (...args: unknown[]) => getProjectDetail(...args),
  addTrackedFile: (...args: unknown[]) => addTrackedFile(...args),
  removeTrackedFile: (...args: unknown[]) => removeTrackedFile(...args),
}));

vi.mock("sonner", () => ({
  toast: {
    success: (...args: unknown[]) => toastSuccess(...args),
    error: (...args: unknown[]) => toastError(...args),
  },
}));

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("ProjectDetailPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const renderPage = () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return render(
      <MemoryRouter initialEntries={["/projects/p1"]}>
        <QueryClientProvider client={qc}>
          <Routes>
            <Route path="/projects/:projectId" element={<ProjectDetailPage />} />
          </Routes>
        </QueryClientProvider>
      </MemoryRouter>,
    );
  };

  it("renders tracked files table and missing warning", async () => {
    getProjectDetail.mockResolvedValue({
      project: {
        id: "p1",
        owner: "user-1",
        name: "Alpha",
        description: "Tracking critical files",
        tags: ["ops"],
        settings: {},
        created_at: "2026-01-01T00:00:00+00:00",
        updated_at: "2026-01-01T00:00:00+00:00",
      },
      files: [
        {
          id: "tf-1",
          project_id: "p1",
          owner: "user-1",
          provider: "local",
          provider_ref: "/workspace/report.csv",
          display_path: "/workspace/report.csv",
          status: "active",
          metadata: {},
          created_at: "2026-01-01T00:00:00+00:00",
          updated_at: "2026-01-01T00:00:00+00:00",
          last_seen_at: "2026-01-01T00:00:00+00:00",
          archived_at: null,
        },
        {
          id: "tf-2",
          project_id: "p1",
          owner: "user-1",
          provider: "local",
          provider_ref: "/workspace/missing.txt",
          display_path: "/workspace/missing.txt",
          status: "missing",
          metadata: {},
          created_at: "2026-01-01T00:00:00+00:00",
          updated_at: "2026-01-01T00:00:00+00:00",
          last_seen_at: null,
          archived_at: null,
        },
      ],
      cursor: null,
    });

    renderPage();

    expect(await screen.findByText("Tracked files")).toBeInTheDocument();
    expect(screen.getByText("/workspace/report.csv")).toBeInTheDocument();
    expect(screen.getByText("/workspace/missing.txt")).toBeInTheDocument();
    expect(screen.getByTestId("missing-files-warning")).toBeInTheDocument();
    expect(screen.getByTestId("tracked-file-row-missing")).toBeInTheDocument();
  });

  it("renders empty state when no tracked files exist", async () => {
    getProjectDetail.mockResolvedValue({
      project: {
        id: "p1",
        owner: "user-1",
        name: "Alpha",
        description: null,
        tags: [],
        settings: {},
        created_at: "2026-01-01T00:00:00+00:00",
        updated_at: "2026-01-01T00:00:00+00:00",
      },
      files: [],
      cursor: null,
    });

    renderPage();

    expect(await screen.findByText("No tracked files")).toBeInTheDocument();
    expect(screen.queryByTestId("tracked-files-table")).not.toBeInTheDocument();
  });

  it("optimistically adds tracked file and rolls back on error", async () => {
    const addDeferred = deferred<unknown>();
    getProjectDetail.mockResolvedValue({
      project: {
        id: "p1",
        owner: "user-1",
        name: "Alpha",
        description: null,
        tags: [],
        settings: {},
        created_at: "2026-01-01T00:00:00+00:00",
        updated_at: "2026-01-01T00:00:00+00:00",
      },
      files: [],
      cursor: null,
    });
    addTrackedFile.mockReturnValue(addDeferred.promise);

    renderPage();

    expect(await screen.findByText("No tracked files")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("File reference"), {
      target: { value: "/workspace/new-file.txt" },
    });
    fireEvent.click(screen.getByRole("button", { name: /add file/i }));

    // Optimistic row appears immediately.
    expect(await screen.findByText("/workspace/new-file.txt")).toBeInTheDocument();

    addDeferred.reject(new Error("missing file"));

    await waitFor(() => {
      expect(screen.queryByText("/workspace/new-file.txt")).not.toBeInTheDocument();
      expect(toastError).toHaveBeenCalledWith("missing file");
    });
  });

  it("optimistically removes tracked file and keeps removal on success", async () => {
    const removeDeferred = deferred<{ ok: boolean; deleted: boolean }>();
    getProjectDetail.mockResolvedValue({
      project: {
        id: "p1",
        owner: "user-1",
        name: "Alpha",
        description: null,
        tags: [],
        settings: {},
        created_at: "2026-01-01T00:00:00+00:00",
        updated_at: "2026-01-01T00:00:00+00:00",
      },
      files: [
        {
          id: "tf-1",
          project_id: "p1",
          owner: "user-1",
          provider: "local",
          provider_ref: "/workspace/delete-me.txt",
          display_path: "/workspace/delete-me.txt",
          status: "active",
          metadata: {},
          created_at: "2026-01-01T00:00:00+00:00",
          updated_at: "2026-01-01T00:00:00+00:00",
          last_seen_at: "2026-01-01T00:00:00+00:00",
          archived_at: null,
        },
      ],
      cursor: null,
    });
    removeTrackedFile.mockReturnValue(removeDeferred.promise);

    renderPage();

    expect(await screen.findByText("/workspace/delete-me.txt")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /remove tracked file/i }));
    fireEvent.click(await screen.findByRole("button", { name: "Remove" }));

    // Optimistic removal hides row immediately.
    await waitFor(() => {
      expect(screen.queryByText("/workspace/delete-me.txt")).not.toBeInTheDocument();
    });

    removeDeferred.resolve({ ok: true, deleted: true });

    await waitFor(() => {
      expect(toastSuccess).toHaveBeenCalledWith("Tracked file removed");
    });
  });
});
