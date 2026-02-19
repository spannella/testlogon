import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { FilePreview } from "../FilePreview";
import type { FileEntry } from "@/api/types";

vi.mock("@/api/endpoints/files", () => ({
  previewUrl: (path: string) => `/v1/fs/preview?path=${encodeURIComponent(path)}`,
}));

const { startPreviewParseJob } = vi.hoisted(() => ({
  startPreviewParseJob: vi.fn(),
}));

vi.mock("@/lib/previewParseWorker", () => ({
  startPreviewParseJob,
}));

vi.mock("mammoth/mammoth.browser", () => ({
  extractRawText: vi.fn(async () => ({ value: "Word body" })),
}));

describe("FilePreview parse worker usage", () => {
  const onClose = vi.fn();
  const onNavigate = vi.fn();
  const onDownload = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, arrayBuffer: async () => new Uint8Array([1]).buffer }));
  });

  it("does not invoke heavy parse worker for docx previews", () => {
    const file: FileEntry = {
      name: "report.docx",
      path: "/report.docx",
      type: "file",
      content_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      preview_kind: "word",
      preview_supported: true,
      preview_reason: "none",
    };

    render(
      <FilePreview
        file={file}
        files={[file]}
        onClose={onClose}
        onNavigate={onNavigate}
        onDownload={onDownload}
      />,
    );

    expect(screen.getByText("report.docx")).toBeInTheDocument();
    expect(screen.queryByText(/Legacy \.doc previews are not supported yet/i)).not.toBeInTheDocument();
    expect(startPreviewParseJob).not.toHaveBeenCalled();
  });

  it("does not invoke heavy parse worker for legacy .doc fallback", () => {
    const file: FileEntry = {
      name: "legacy.doc",
      path: "/legacy.doc",
      type: "file",
      content_type: "application/msword",
      preview_kind: "word",
      preview_supported: true,
      preview_reason: "none",
    };

    render(
      <FilePreview
        file={file}
        files={[file]}
        onClose={onClose}
        onNavigate={onNavigate}
        onDownload={onDownload}
      />,
    );

    expect(screen.getByText(/Legacy \.doc previews are not supported yet/i)).toBeInTheDocument();
    expect(startPreviewParseJob).not.toHaveBeenCalled();
  });
});
