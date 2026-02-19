import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { FilePreview } from "../FilePreview";
import type { FileEntry } from "@/api/types";

vi.mock("@/api/endpoints/files", () => ({
  previewUrl: (path: string) => `/v1/fs/preview?path=${encodeURIComponent(path)}`,
}));

vi.mock("xlsx", () => ({
  read: vi.fn(() => ({
    SheetNames: ["Summary", "Details"],
    Sheets: { Summary: {}, Details: {} },
  })),
  utils: {
    sheet_to_json: vi.fn((_sheet: unknown, _opts: unknown) => [
      ["name", "amount"],
      ["alpha", "10"],
      ["beta", "20"],
    ]),
  },
}));

const { parquetReadObjects } = vi.hoisted(() => ({
  parquetReadObjects: vi.fn(async () => [
    { id: 1, city: "Berlin", active: true },
    { id: 2, city: "London", active: false },
  ]),
}));

vi.mock("hyparquet", () => ({
  parquetReadObjects,
}));

const { extractRawText } = vi.hoisted(() => ({
  extractRawText: vi.fn(async () => ({
    value: "Quarterly report\nRevenue grew 14%",
  })),
}));

vi.mock("mammoth/mammoth.browser", () => ({
  extractRawText,
}));

describe("FilePreview dispatcher", () => {
  const onClose = vi.fn();
  const onNavigate = vi.fn();
  const onDownload = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, text: async () => "hello" }));
  });

  function renderPreview(file: FileEntry) {
    return render(
      <FilePreview
        file={file}
        files={[file]}
        onClose={onClose}
        onNavigate={onNavigate}
        onDownload={onDownload}
      />,
    );
  }

  it("renders text preview for preview_kind=text", async () => {
    renderPreview({
      name: "a.txt",
      path: "/a.txt",
      type: "file",
      content_type: "text/plain",
      preview_kind: "text",
      preview_supported: true,
      preview_reason: "none",
    });

    expect(await screen.findByText("hello")).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Close preview dialog/i })).toBeInTheDocument();
  });

  it("renders image preview for preview_kind=image", () => {
    const { container } = renderPreview({
      name: "a.png",
      path: "/a.png",
      type: "file",
      content_type: "image/png",
      preview_kind: "image",
      preview_supported: true,
      preview_reason: "none",
    });

    expect(container.querySelector("img")).toBeTruthy();
  });

  it("renders unsupported fallback with explicit reason", () => {
    renderPreview({
      name: "a.bin",
      path: "/a.bin",
      type: "file",
      content_type: "application/octet-stream",
      preview_kind: "none",
      preview_supported: false,
      preview_reason: "unsupported_type",
    });

    expect(screen.getByText(/Preview not available for this file type/i)).toBeInTheDocument();
  });

  it("uses provided previewSrcUrl (shared parity)", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, text: async () => "shared-content" });
    vi.stubGlobal("fetch", fetchMock);

    render(
      <FilePreview
        file={{
          name: "shared.txt",
          path: "/shared.txt",
          type: "file",
          content_type: "text/plain",
          preview_kind: "text",
          preview_supported: true,
          preview_reason: "none",
        }}
        files={[
          {
            name: "shared.txt",
            path: "/shared.txt",
            type: "file",
            content_type: "text/plain",
            preview_kind: "text",
            preview_supported: true,
            preview_reason: "none",
          },
        ]}
        onClose={onClose}
        onNavigate={onNavigate}
        onDownload={onDownload}
        previewSrcUrl="/v1/fs/shared-preview?owner=alice&path=%2Fshared.txt"
      />,
    );

    expect(await screen.findByText("shared-content")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith("/v1/fs/shared-preview?owner=alice&path=%2Fshared.txt", expect.any(Object));
  });


  it("renders PDF controls and updates page/zoom", async () => {
    const { container } = renderPreview({
      name: "doc.pdf",
      path: "/doc.pdf",
      type: "file",
      content_type: "application/pdf",
      preview_kind: "pdf",
      preview_supported: true,
      preview_reason: "none",
      size: 1024,
    });

    const nextPage = screen.getByRole("button", { name: /next page/i });
    const zoomIn = screen.getByRole("button", { name: /zoom in/i });
    fireEvent.click(nextPage);
    fireEvent.click(zoomIn);

    const frame = container.querySelector("iframe");
    await waitFor(() => {
      expect(frame?.getAttribute("src")).toContain("#page=2&zoom=110");
    });
  });

  it("falls back for oversized PDFs", () => {
    renderPreview({
      name: "large.pdf",
      path: "/large.pdf",
      type: "file",
      content_type: "application/pdf",
      preview_kind: "pdf",
      preview_supported: true,
      preview_reason: "none",
      size: 30 * 1024 * 1024,
    });

    expect(screen.getByText(/exceeds the inline preview size limit/i)).toBeInTheDocument();
  });


  it("renders image controls and updates zoom", async () => {
    const { container } = renderPreview({
      name: "img.png",
      path: "/img.png",
      type: "file",
      content_type: "image/png",
      preview_kind: "image",
      preview_supported: true,
      preview_reason: "none",
      size: 1024,
    });

    fireEvent.click(screen.getByRole("button", { name: /image zoom in/i }));
    const image = container.querySelector("img");
    await waitFor(() => {
      expect(image?.getAttribute("style")).toContain("scale(1.1)");
    });
  });

  it("falls back for oversized images", () => {
    renderPreview({
      name: "huge.jpg",
      path: "/huge.jpg",
      type: "file",
      content_type: "image/jpeg",
      preview_kind: "image",
      preview_supported: true,
      preview_reason: "none",
      size: 45 * 1024 * 1024,
    });

    expect(screen.getByText(/image exceeds the inline preview size limit/i)).toBeInTheDocument();
  });


  it("renders line numbers and syntax highlighting for common code", async () => {
    const source = "const answer = 42;\nreturn answer;";
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, text: async () => source }));

    renderPreview({
      name: "main.ts",
      path: "/main.ts",
      type: "file",
      content_type: "text/typescript",
      preview_kind: "text",
      preview_supported: true,
      preview_reason: "none",
    });

    expect(await screen.findByText("1")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
    const kw = screen.getByText("const");
    expect(kw.className).toContain("text-fuchsia-700");
  });

  it("escapes html/script in text preview", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, text: async () => '<script>window.__pwned=true</script>' }));

    renderPreview({
      name: "index.html",
      path: "/index.html",
      type: "file",
      content_type: "text/html",
      preview_kind: "text",
      preview_supported: true,
      preview_reason: "none",
    });

    expect(await screen.findByText((_, node) => node?.textContent === '<script>window.__pwned=true</script>')).toBeInTheDocument();
    expect((window as any).__pwned).toBeUndefined();
  });


  it("renders Excel preview with sheet selector and virtualization window", async () => {
    const bytes = new Uint8Array([80, 75, 3, 4]).buffer;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, arrayBuffer: async () => bytes }));

    renderPreview({
      name: "book.xlsx",
      path: "/book.xlsx",
      type: "file",
      content_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      preview_kind: "excel",
      preview_supported: true,
      preview_reason: "none",
    });

    expect(await screen.findByLabelText(/Excel sheet selector/i)).toBeInTheDocument();
    expect(screen.getByText("Summary")).toBeInTheDocument();
    expect(screen.getByText("alpha")).toBeInTheDocument();
  });

  it("renders Parquet preview table with virtualization", async () => {
    const bytes = new Uint8Array([80, 65, 82, 49]).buffer;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, arrayBuffer: async () => bytes }));

    renderPreview({
      name: "events.parquet",
      path: "/events.parquet",
      type: "file",
      content_type: "application/parquet",
      preview_kind: "parquet",
      preview_supported: true,
      preview_reason: "none",
    });

    expect(await screen.findByText(/Parquet table preview/i)).toBeInTheDocument();
    expect(screen.getByText("city")).toBeInTheDocument();
    expect(screen.getByText("Berlin")).toBeInTheDocument();
    expect(parquetReadObjects).toHaveBeenCalled();
  });

  it("renders DOCX preview as readable text", async () => {
    const bytes = new Uint8Array([80, 75, 3, 4]).buffer;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, arrayBuffer: async () => bytes }));

    renderPreview({
      name: "report.docx",
      path: "/report.docx",
      type: "file",
      content_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      preview_kind: "word",
      preview_supported: true,
      preview_reason: "none",
    });

    expect(screen.getByText("report.docx")).toBeInTheDocument();
    expect(screen.queryByText(/Legacy \.doc previews are not supported yet/i)).not.toBeInTheDocument();
  });

  it("renders DOCX content as text without script execution", async () => {
    const bytes = new Uint8Array([80, 75, 3, 4]).buffer;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, arrayBuffer: async () => bytes }));
    (window as any).__docx_pwned = undefined;

    renderPreview({
      name: "x.docx",
      path: "/x.docx",
      type: "file",
      content_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      preview_kind: "word",
      preview_supported: true,
      preview_reason: "none",
    });

    expect(await screen.findByText("x.docx")).toBeInTheDocument();
    expect((window as any).__docx_pwned).toBeUndefined();
  });

  it("shows explicit unsupported fallback for legacy .doc", () => {
    renderPreview({
      name: "legacy.doc",
      path: "/legacy.doc",
      type: "file",
      content_type: "application/msword",
      preview_kind: "word",
      preview_supported: true,
      preview_reason: "none",
    });

    expect(screen.getByText(/Legacy \.doc previews are not supported yet/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Download to view/i })).toBeInTheDocument();
  });

  it("renders CSV preview table with detected delimiter and header toggle", async () => {
    const csv = "name;age;role\nAlice;31;Engineer\nBob;29;Designer";
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, text: async () => csv }));

    renderPreview({
      name: "team.csv",
      path: "/team.csv",
      type: "file",
      content_type: "text/csv",
      preview_kind: "csv",
      preview_supported: true,
      preview_reason: "none",
    });

    expect(await screen.findByText("Detected delimiter:")).toBeInTheDocument();
    expect(screen.getByRole("table", { name: /CSV preview table for team.csv/i })).toBeInTheDocument();
    expect(screen.getByText("name")).toBeInTheDocument();
    expect(screen.getByText("Alice")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Use row 1 as data/i }));
    expect(await screen.findByText("Column 1")).toBeInTheDocument();
  });

  it("shows deterministic truncation messaging for oversized CSV tables", async () => {
    const header = "c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15,c16,c17,c18,c19,c20,c21,c22,c23,c24,c25,c26,c27,c28,c29,c30,c31,c32,c33,c34,c35,c36,c37,c38,c39,c40,c41";
    const row = "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41";
    const lines = [header, ...Array.from({ length: 220 }, () => row)];
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, text: async () => lines.join("\n") }));

    renderPreview({
      name: "wide.csv",
      path: "/wide.csv",
      type: "file",
      content_type: "text/csv",
      preview_kind: "csv",
      preview_supported: true,
      preview_reason: "none",
    });

    expect(await screen.findByText(/Preview truncated to 200 rows and 40 columns/i)).toBeInTheDocument();
  });

  it("falls back deterministically when preview is marked unsupported", () => {
    renderPreview({
      name: "budget.csv",
      path: "/budget.csv",
      type: "file",
      content_type: "text/csv",
      preview_kind: "csv",
      preview_supported: false,
      preview_reason: "too_large",
    });

    expect(screen.getByText(/exceeds the inline preview size limit/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Download to view/i })).toBeInTheDocument();
  });

  it("infers renderer kind from content-type when preview_kind is missing", async () => {
    const bytes = new Uint8Array([80, 75, 3, 4]).buffer;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, arrayBuffer: async () => bytes }));

    renderPreview({
      name: "implicit.docx",
      path: "/implicit.docx",
      type: "file",
      content_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      preview_supported: true,
      preview_reason: "none",
    });

    await waitFor(() => expect(extractRawText).toHaveBeenCalled());
    expect(await screen.findByText(/Quarterly report/i)).toBeInTheDocument();
  });

  it("renders escaped text literals without creating active DOM nodes", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: true, text: async () => '<img src=x onerror="window.__text_pwned=true">' }),
    );
    (window as { __text_pwned?: boolean }).__text_pwned = undefined;

    const { container } = renderPreview({
      name: "unsafe.html",
      path: "/unsafe.html",
      type: "file",
      content_type: "text/html",
      preview_kind: "text",
      preview_supported: true,
      preview_reason: "none",
    });

    const escapedMatches = await screen.findAllByText((_, node) => node?.textContent?.includes('window.__text_pwned=true') ?? false);
    expect(escapedMatches.length).toBeGreaterThan(0);
    expect(container.querySelector("img[src='x']")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect((window as { __text_pwned?: boolean }).__text_pwned).toBeUndefined();
  });

  it("renders escaped DOCX text literals without creating active DOM nodes", async () => {
    const bytes = new Uint8Array([80, 75, 3, 4]).buffer;
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, arrayBuffer: async () => bytes }));
    extractRawText.mockResolvedValueOnce({
      value: '<svg onload="window.__docx_pwned=true"></svg>',
    });
    (window as { __docx_pwned?: boolean }).__docx_pwned = undefined;

    const { container } = renderPreview({
      name: "unsafe.docx",
      path: "/unsafe.docx",
      type: "file",
      content_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      preview_kind: "word",
      preview_supported: true,
      preview_reason: "none",
    });

    expect(await screen.findByText('<svg onload="window.__docx_pwned=true"></svg>')).toBeInTheDocument();
    expect(container.querySelector("svg[onload]" )).toBeNull();
    expect((window as { __docx_pwned?: boolean }).__docx_pwned).toBeUndefined();
  });

});
