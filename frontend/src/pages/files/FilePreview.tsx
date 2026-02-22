import { useState, useEffect, useCallback, useRef, type ReactNode } from "react";
import { Download, X, ChevronLeft, ChevronRight, FileText, FileImage, FileAudio, FileVideo, File, Minus, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { previewUrl } from "@/api/endpoints/files";
import type { FileEntry, PreviewKind } from "@/api/types";
import * as XLSX from "xlsx";
import { parquetReadObjects } from "hyparquet";
import * as mammoth from "mammoth/mammoth.browser";

function fileIcon(ct?: string) {
  if (!ct) return <File className="h-5 w-5" />;
  if (ct.startsWith("image/")) return <FileImage className="h-5 w-5" />;
  if (ct.startsWith("audio/")) return <FileAudio className="h-5 w-5" />;
  if (ct.startsWith("video/")) return <FileVideo className="h-5 w-5" />;
  if (ct === "application/pdf" || ct.startsWith("text/")) return <FileText className="h-5 w-5" />;
  return <File className="h-5 w-5" />;
}

function formatBytes(bytes?: number): string {
  if (bytes == null) return "";
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + (sizes[i] ?? "TB");
}

interface FilePreviewProps {
  file: FileEntry;
  files: FileEntry[];
  onClose: () => void;
  onNavigate: (file: FileEntry) => void;
  onDownload: (file: FileEntry) => void;
  onForgetRemembered?: (file: FileEntry) => void;
  previewSrcUrl?: string;
}

function resolvePreviewKind(file: FileEntry): PreviewKind {
  if (file.preview_kind) return file.preview_kind;
  const ct = file.content_type ?? "";
  if (ct.startsWith("image/")) return "image";
  if (ct === "application/pdf") return "pdf";
  if (ct === "text/csv" || ct === "application/csv") return "csv";
  if (
    ct === "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" ||
    ct === "application/vnd.ms-excel"
  ) {
    return "excel";
  }
  if (
    ct === "application/parquet" ||
    ct === "application/vnd.apache.parquet" ||
    ct === "application/octet-stream+parquet"
  ) {
    return "parquet";
  }
  if (
    ct === "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ||
    ct === "application/msword"
  ) {
    return "word";
  }
  if (ct.startsWith("text/") || ct === "application/json" || ct === "application/xml") return "text";
  return "none";
}

function UnsupportedPreview({ file, onDownload, reason }: { file: FileEntry; onDownload: (file: FileEntry) => void; reason?: string }) {
  const msgByReason: Record<string, string> = {
    encrypted: "This file is encrypted client-side. Download it and enter the password to decrypt locally.",
    unsupported_type: "Preview not available for this file type.",
    not_enabled: "Preview for this file type is not enabled yet.",
    too_large: "Preview unavailable because this PDF exceeds the inline preview size limit.",
    image_too_large: "Preview unavailable because this image exceeds the inline preview size limit.",
    parse_failed: "Preview failed to load. You can retry or download the file.",
    parse_timeout: "Preview timed out. Try downloading this file for full fidelity.",
    image_failed: "Image preview failed to load. You can retry or download the file.",
    legacy_word_unsupported: "Legacy .doc previews are not supported yet. Download to open this file.",
    unknown: "Preview is currently unavailable.",
    none: "Preview is currently unavailable.",
  };
  const msg = msgByReason[reason || "unknown"] ?? msgByReason.unknown;
  return (
    <div className="flex max-w-md flex-col items-center gap-4 text-center">
      {fileIcon(file.content_type)}
      <p className="text-sm text-muted-foreground">{msg}</p>
      <Button variant="outline" size="sm" onClick={() => onDownload(file)}>
        <Download className="mr-1 h-3.5 w-3.5" /> Download to view
      </Button>
    </div>
  );
}


const PDF_PREVIEW_MAX_BYTES = 25 * 1024 * 1024;
const IMAGE_PREVIEW_MAX_BYTES = 40 * 1024 * 1024;
const PREVIEW_MAX_BYTES = 10 * 1024 * 1024;
const CSV_PREVIEW_MAX_ROWS = 200;
const CSV_PREVIEW_MAX_COLS = 40;
const EXCEL_PREVIEW_MAX_ROWS = 50000;
const EXCEL_PREVIEW_MAX_COLS = 120;
const EXCEL_ROW_HEIGHT_PX = 30;
const EXCEL_VIEWPORT_HEIGHT_PX = 420;
const PARQUET_PREVIEW_MAX_ROWS = 20000;
const PARQUET_PREVIEW_MAX_COLS = 120;
const PARQUET_ROW_HEIGHT_PX = 30;
const PARQUET_VIEWPORT_HEIGHT_PX = 420;
const PREVIEW_PARSE_TIMEOUT_MS = 8_000;
const TEXT_PREVIEW_MAX_LINES = 5000;

function parseTimeoutController() {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), PREVIEW_PARSE_TIMEOUT_MS);
  return {
    controller,
    clear: () => window.clearTimeout(timer),
  };
}

function isDocxFile(file: FileEntry): boolean {
  const name = file.name.toLowerCase();
  const ct = (file.content_type ?? "").toLowerCase();
  return (
    name.endsWith(".docx") ||
    ct === "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
  );
}

function isLegacyDocFile(file: FileEntry): boolean {
  const name = file.name.toLowerCase();
  const ct = (file.content_type ?? "").toLowerCase();
  return name.endsWith(".doc") || ct === "application/msword";
}

function ImagePreview({ file, url, onDownload }: { file: FileEntry; url: string; onDownload: (file: FileEntry) => void }) {
  const [zoom, setZoom] = useState(100);
  const [fitMode, setFitMode] = useState<"fit" | "actual">("fit");
  const [failed, setFailed] = useState(false);

  if ((file.size ?? 0) > IMAGE_PREVIEW_MAX_BYTES) {
    return <UnsupportedPreview file={file} onDownload={onDownload} reason="image_too_large" />;
  }

  if (failed) {
    return (
      <div className="flex max-w-md flex-col items-center gap-3 text-center">
        <UnsupportedPreview file={file} onDownload={onDownload} reason="image_failed" />
        <Button variant="ghost" size="sm" onClick={() => setFailed(false)}>
          Retry preview
        </Button>
      </div>
    );
  }

  return (
    <div className="flex h-full w-full max-w-5xl flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border bg-muted/30 px-3 py-2">
        <div className="flex items-center gap-2 text-xs">
          <span className="text-muted-foreground">Zoom</span>
          <Button variant="outline" size="sm" onClick={() => setZoom((z) => Math.max(25, z - 10))} aria-label="Image zoom out">
            <Minus className="h-3.5 w-3.5" />
          </Button>
          <span className="min-w-[3rem] text-center font-medium">{zoom}%</span>
          <Button variant="outline" size="sm" onClick={() => setZoom((z) => Math.min(400, z + 10))} aria-label="Image zoom in">
            <Plus className="h-3.5 w-3.5" />
          </Button>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setFitMode((mode) => (mode === "fit" ? "actual" : "fit"))}
          aria-label="Toggle fit mode"
        >
          {fitMode === "fit" ? "Actual size" : "Fit to screen"}
        </Button>
      </div>
      <div className="flex h-full min-h-[28rem] items-center justify-center overflow-auto rounded-lg border bg-black/5 p-4">
        <img
          src={url}
          alt={file.name}
          className={fitMode === "fit" ? "max-h-full max-w-full object-contain" : "object-none"}
          style={{ transform: `scale(${zoom / 100})`, transformOrigin: "center" }}
          onError={() => setFailed(true)}
        />
      </div>
    </div>
  );
}

function PdfPreview({ file, url, onDownload }: { file: FileEntry; url: string; onDownload: (file: FileEntry) => void }) {
  const [page, setPage] = useState(1);
  const [zoom, setZoom] = useState(100);
  const [failed, setFailed] = useState(false);
  const loadedRef = useRef(false);

  useEffect(() => {
    loadedRef.current = false;
    setFailed(false);
    const timeout = window.setTimeout(() => {
      if (!loadedRef.current) {
        setFailed(true);
      }
    }, 8000);
    return () => window.clearTimeout(timeout);
  }, [url, page, zoom]);

  if ((file.size ?? 0) > PDF_PREVIEW_MAX_BYTES) {
    return <UnsupportedPreview file={file} onDownload={onDownload} reason="too_large" />;
  }

  if (failed) {
    return (
      <div className="flex max-w-md flex-col items-center gap-3 text-center">
        <UnsupportedPreview file={file} onDownload={onDownload} reason="parse_failed" />
        <Button variant="ghost" size="sm" onClick={() => { setFailed(false); }}>
          Retry preview
        </Button>
      </div>
    );
  }

  const src = `${url}#page=${page}&zoom=${zoom}`;

  return (
    <div className="flex h-full w-full max-w-5xl flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border bg-muted/30 px-3 py-2">
        <div className="flex items-center gap-2 text-xs">
          <span className="text-muted-foreground">Page</span>
          <Button variant="outline" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} aria-label="Previous page">
            <ChevronLeft className="h-3.5 w-3.5" />
          </Button>
          <span className="min-w-[3rem] text-center font-medium">{page}</span>
          <Button variant="outline" size="sm" onClick={() => setPage((p) => p + 1)} aria-label="Next page">
            <ChevronRight className="h-3.5 w-3.5" />
          </Button>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="text-muted-foreground">Zoom</span>
          <Button variant="outline" size="sm" onClick={() => setZoom((z) => Math.max(50, z - 10))} aria-label="Zoom out">
            <Minus className="h-3.5 w-3.5" />
          </Button>
          <span className="min-w-[3rem] text-center font-medium">{zoom}%</span>
          <Button variant="outline" size="sm" onClick={() => setZoom((z) => Math.min(300, z + 10))} aria-label="Zoom in">
            <Plus className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
      <iframe
        src={src}
        title={file.name}
        className="h-full min-h-[28rem] w-full rounded-lg border"
        onLoad={() => { loadedRef.current = true; }}
      />
    </div>
  );
}

type CsvParseResult = {
  rows: string[][];
  rowTruncated: boolean;
  colTruncated: boolean;
};

function detectCsvDelimiter(content: string): string {
  const candidates = [",", ";", "\t", "|"];
  const lines = content
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(0, 30);

  if (lines.length === 0) return ",";

  let best = ",";
  let bestScore = -1;

  for (const delimiter of candidates) {
    const counts = lines.map((line) => {
      let inQuotes = false;
      let count = 0;
      for (let i = 0; i < line.length; i += 1) {
        const char = line[i];
        if (char === '"') {
          if (inQuotes && line[i + 1] === '"') {
            i += 1;
          } else {
            inQuotes = !inQuotes;
          }
          continue;
        }
        if (!inQuotes && char === delimiter) count += 1;
      }
      return count;
    });
    const populated = counts.filter((count) => count > 0);
    if (populated.length === 0) continue;
    const avg = populated.reduce((sum, value) => sum + value, 0) / populated.length;
    const variance = populated.reduce((sum, value) => sum + (value - avg) ** 2, 0) / populated.length;
    const score = avg - variance;
    if (score > bestScore) {
      bestScore = score;
      best = delimiter;
    }
  }

  return best;
}

function parseCsvWithLimits(content: string, delimiter: string): CsvParseResult {
  const normalized = content.replace(/\r\n/g, "\n");
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let inQuotes = false;
  let rowTruncated = false;
  let colTruncated = false;

  const pushCell = () => {
    if (row.length < CSV_PREVIEW_MAX_COLS) {
      row.push(cell);
    } else {
      colTruncated = true;
    }
    cell = "";
  };

  const pushRow = () => {
    if (rows.length < CSV_PREVIEW_MAX_ROWS) {
      rows.push(row);
    } else {
      rowTruncated = true;
    }
    row = [];
  };

  for (let i = 0; i < normalized.length; i += 1) {
    const char = normalized[i];
    if (char === '"') {
      if (inQuotes && normalized[i + 1] === '"') {
        cell += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (!inQuotes && char === delimiter) {
      pushCell();
      continue;
    }
    if (!inQuotes && char === "\n") {
      pushCell();
      pushRow();
      if (rowTruncated) break;
      continue;
    }
    cell += char;
  }

  if (inQuotes) {
    throw new Error("Unclosed quoted field in CSV preview");
  }

  if (cell.length > 0 || row.length > 0) {
    pushCell();
    pushRow();
  }

  return { rows, rowTruncated, colTruncated };
}

function CsvTablePreview({ file, url, onDownload }: { file: FileEntry; url: string; onDownload: (file: FileEntry) => void }) {
  const [rows, setRows] = useState<string[][] | null>(null);
  const [delimiter, setDelimiter] = useState(",");
  const [parseError, setParseError] = useState(false);
  const [parseTimeout, setParseTimeout] = useState(false);
  const [rowTruncated, setRowTruncated] = useState(false);
  const [colTruncated, setColTruncated] = useState(false);
  const [useHeaderRow, setUseHeaderRow] = useState(true);

  useEffect(() => {
    const timeout = parseTimeoutController();
    setRows(null);
    setParseError(false);
    setParseTimeout(false);
    setRowTruncated(false);
    setColTruncated(false);

    if ((file.size ?? 0) > PREVIEW_MAX_BYTES) {
      setParseError(true);
      timeout.clear();
      return () => timeout.controller.abort();
    }

    fetch(url, { signal: timeout.controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error("CSV preview fetch failed");
        return response.text();
      })
      .then((content) => {
        const chosenDelimiter = detectCsvDelimiter(content);
        const parsed = parseCsvWithLimits(content, chosenDelimiter);
        setDelimiter(chosenDelimiter);
        setRows(parsed.rows);
        setRowTruncated(parsed.rowTruncated);
        setColTruncated(parsed.colTruncated);
      })
      .catch((error) => {
        if ((error as Error).name === "AbortError") {
          setParseTimeout(true);
          return;
        }
        setParseError(true);
      })
      .finally(() => {
        timeout.clear();
      });

    return () => {
      timeout.clear();
      timeout.controller.abort();
    };
  }, [file.size, url]);

  if ((file.size ?? 0) > PREVIEW_MAX_BYTES) {
    return <UnsupportedPreview file={file} onDownload={onDownload} reason="too_large" />;
  }

  if (parseTimeout) {
    return <UnsupportedPreview file={file} onDownload={onDownload} reason="parse_timeout" />;
  }

  if (parseError) {
    return <UnsupportedPreview file={file} onDownload={onDownload} reason="parse_failed" />;
  }

  if (!rows) {
    return <p className="text-sm text-muted-foreground animate-pulse" aria-live="polite">Loading CSV preview...</p>;
  }

  if (rows.length === 0) {
    return <p className="text-sm text-muted-foreground">This CSV file is empty.</p>;
  }

  const header = useHeaderRow ? rows[0] ?? [] : [];
  const dataRows = useHeaderRow ? rows.slice(1) : rows;
  const maxCols = Math.max(header.length, ...dataRows.map((row) => row.length));
  const fallbackHeaders = Array.from({ length: maxCols }, (_, index) => `Column ${index + 1}`);
  const delimLabel = delimiter === "\t" ? "TAB" : delimiter;

  return (
    <div className="flex h-full w-full max-w-6xl flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border bg-muted/30 px-3 py-2 text-xs">
        <span className="text-muted-foreground">Detected delimiter: <span className="font-medium text-foreground">{delimLabel}</span></span>
        <Button variant="outline" size="sm" onClick={() => setUseHeaderRow((value) => !value)}>
          {useHeaderRow ? "Use row 1 as data" : "Use row 1 as header"}
        </Button>
      </div>

      {(rowTruncated || colTruncated) && (
        <p className="text-xs text-muted-foreground">
          Preview truncated to {CSV_PREVIEW_MAX_ROWS} rows and {CSV_PREVIEW_MAX_COLS} columns.
        </p>
      )}

      <div className="overflow-auto rounded-lg border">
        <table className="w-full border-collapse text-xs">
          <caption className="sr-only">CSV preview table for {file.name}</caption>
          <thead className="bg-muted/50">
            <tr>
              {(useHeaderRow ? header : fallbackHeaders).map((title, index) => (
                <th key={`h-${index}`} scope="col" className="border-b px-3 py-2 text-left font-medium">
                  {title || fallbackHeaders[index]}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {dataRows.map((row, rowIndex) => (
              <tr key={`r-${rowIndex}`} className="odd:bg-background even:bg-muted/20">
                {Array.from({ length: maxCols }, (_, colIndex) => (
                  <td key={`r-${rowIndex}-c-${colIndex}`} className="border-b px-3 py-1.5 align-top">
                    {row[colIndex] ?? ""}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}


type ExcelSheetData = {
  name: string;
  rows: string[][];
  rowTruncated: boolean;
  colTruncated: boolean;
};

function normalizeExcelCell(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (value instanceof Date) return value.toISOString();
  return JSON.stringify(value);
}

function parseExcelWorkbook(buffer: ArrayBuffer): ExcelSheetData[] {
  const workbook = XLSX.read(buffer, { type: "array", cellDates: true });
  return workbook.SheetNames.map((sheetName) => {
    const sheet = workbook.Sheets[sheetName];
    const matrix = sheet
      ? (XLSX.utils.sheet_to_json(sheet, { header: 1, raw: false }) as unknown[][])
      : [];

    let rowTruncated = false;
    let colTruncated = false;
    const rows: string[][] = [];

    for (const sourceRow of matrix) {
      if (rows.length >= EXCEL_PREVIEW_MAX_ROWS) {
        rowTruncated = true;
        break;
      }
      const normalizedRow = sourceRow
        .slice(0, EXCEL_PREVIEW_MAX_COLS)
        .map((cell) => normalizeExcelCell(cell));
      if (sourceRow.length > EXCEL_PREVIEW_MAX_COLS) colTruncated = true;
      rows.push(normalizedRow);
    }

    return {
      name: sheetName,
      rows,
      rowTruncated,
      colTruncated,
    };
  });
}

function ExcelTablePreview({ file, url, onDownload }: { file: FileEntry; url: string; onDownload: (file: FileEntry) => void }) {
  const [sheets, setSheets] = useState<ExcelSheetData[] | null>(null);
  const [activeSheet, setActiveSheet] = useState(0);
  const [parseError, setParseError] = useState(false);
  const [parseTimeout, setParseTimeout] = useState(false);
  const [scrollTop, setScrollTop] = useState(0);

  useEffect(() => {
    const timeout = parseTimeoutController();
    setSheets(null);
    setActiveSheet(0);
    setParseError(false);
    setParseTimeout(false);

    if ((file.size ?? 0) > PREVIEW_MAX_BYTES) {
      setParseError(true);
      timeout.clear();
      return () => timeout.controller.abort();
    }

    fetch(url, { signal: timeout.controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error("Excel preview fetch failed");
        return response.arrayBuffer();
      })
      .then((buffer) => {
        const parsedSheets = parseExcelWorkbook(buffer);
        setSheets(parsedSheets);
      })
      .catch((error) => {
        if ((error as Error).name === "AbortError") {
          setParseTimeout(true);
          return;
        }
        setParseError(true);
      })
      .finally(() => {
        timeout.clear();
      });

    return () => {
      timeout.clear();
      timeout.controller.abort();
    };
  }, [file.size, url]);

  const currentSheet = sheets?.[activeSheet] ?? null;

  if (parseTimeout) {
    return <UnsupportedPreview file={file} onDownload={onDownload} reason="parse_timeout" />;
  }

  if (parseError) {
    return <UnsupportedPreview file={file} onDownload={onDownload} reason="parse_failed" />;
  }

  if (!sheets) {
    return <p className="text-sm text-muted-foreground animate-pulse" aria-live="polite">Loading Excel preview...</p>;
  }

  if (sheets.length === 0 || !currentSheet) {
    return <p className="text-sm text-muted-foreground">Workbook has no readable sheets.</p>;
  }

  const rows = currentSheet.rows;
  const header = rows[0] ?? [];
  const dataRows = rows.slice(1);
  const columnCount = Math.max(header.length, ...dataRows.map((row) => row.length), 0);

  const viewportRows = Math.max(1, Math.ceil(EXCEL_VIEWPORT_HEIGHT_PX / EXCEL_ROW_HEIGHT_PX));
  const startRow = Math.max(0, Math.floor(scrollTop / EXCEL_ROW_HEIGHT_PX) - 6);
  const endRow = Math.min(dataRows.length, startRow + viewportRows + 12);
  const visibleRows = dataRows.slice(startRow, endRow);
  const topSpacer = startRow * EXCEL_ROW_HEIGHT_PX;
  const bottomSpacer = Math.max(0, (dataRows.length - endRow) * EXCEL_ROW_HEIGHT_PX);
  const fallbackHeaders = Array.from({ length: columnCount }, (_, index) => `Column ${index + 1}`);

  return (
    <div className="flex h-full w-full max-w-6xl flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border bg-muted/30 px-3 py-2 text-xs">
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground">Sheet</span>
          <select
            aria-label="Excel sheet selector"
            className="rounded border bg-background px-2 py-1 text-xs"
            value={String(activeSheet)}
            onChange={(event) => {
              setActiveSheet(Number(event.target.value));
              setScrollTop(0);
            }}
          >
            {sheets.map((sheet, index) => (
              <option key={sheet.name} value={index}>
                {sheet.name}
              </option>
            ))}
          </select>
        </div>
        <span className="text-muted-foreground">
          Showing {dataRows.length.toLocaleString()} rows ({columnCount} columns)
        </span>
      </div>

      {(currentSheet.rowTruncated || currentSheet.colTruncated) && (
        <p className="text-xs text-muted-foreground">
          Preview truncated to {EXCEL_PREVIEW_MAX_ROWS.toLocaleString()} rows and {EXCEL_PREVIEW_MAX_COLS} columns per sheet.
        </p>
      )}

      <div className="overflow-auto rounded-lg border">
        <table className="w-full border-collapse text-xs">
          <caption className="sr-only">Excel preview table for {file.name}</caption>
          <thead className="bg-muted/50">
            <tr>
              {(header.length ? header : fallbackHeaders).map((title, index) => (
                <th key={`eh-${index}`} scope="col" className="border-b px-3 py-2 text-left font-medium">
                  {title || fallbackHeaders[index]}
                </th>
              ))}
            </tr>
          </thead>
        </table>

        <div
          className="overflow-auto"
          aria-label="Excel row viewport"
          style={{ maxHeight: `${EXCEL_VIEWPORT_HEIGHT_PX}px` }}
          onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
        >
          <div style={{ height: `${topSpacer}px` }} />
          <table className="w-full border-collapse text-xs">
            <tbody>
              {visibleRows.map((row, visibleIndex) => {
                const absoluteIndex = startRow + visibleIndex;
                return (
                  <tr
                    key={`er-${absoluteIndex}`}
                    className="odd:bg-background even:bg-muted/20"
                    style={{ height: `${EXCEL_ROW_HEIGHT_PX}px` }}
                  >
                    {Array.from({ length: columnCount }, (_, colIndex) => (
                      <td key={`er-${absoluteIndex}-c-${colIndex}`} className="border-b px-3 py-1.5 align-top">
                        {row[colIndex] ?? ""}
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
          <div style={{ height: `${bottomSpacer}px` }} />
        </div>
      </div>
    </div>
  );
}

type ParquetPreviewData = {
  columns: string[];
  rows: string[][];
  rowTruncated: boolean;
  colTruncated: boolean;
};

function parquetBufferAdapter(bytes: Uint8Array) {
  return {
    byteLength: bytes.byteLength,
    slice(start: number, end?: number): ArrayBuffer {
      const finish = end ?? bytes.byteLength;
      return bytes.slice(start, finish).buffer;
    },
  };
}

function normalizeParquetCell(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (value instanceof Date) return value.toISOString();
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function parseParquetRows(rows: Record<string, unknown>[]): ParquetPreviewData {
  const discoveredColumns: string[] = [];
  for (const row of rows) {
    for (const key of Object.keys(row)) {
      if (!discoveredColumns.includes(key)) discoveredColumns.push(key);
    }
    if (discoveredColumns.length >= PARQUET_PREVIEW_MAX_COLS) break;
  }

  const colTruncated = discoveredColumns.length >= PARQUET_PREVIEW_MAX_COLS;
  const columns = discoveredColumns.slice(0, PARQUET_PREVIEW_MAX_COLS);
  const rowTruncated = rows.length > PARQUET_PREVIEW_MAX_ROWS;
  const limitedRows = rows.slice(0, PARQUET_PREVIEW_MAX_ROWS);

  const matrix = limitedRows.map((row) => columns.map((column) => normalizeParquetCell(row[column])));

  return {
    columns,
    rows: matrix,
    rowTruncated,
    colTruncated,
  };
}

function ParquetTablePreview({ file, url, onDownload }: { file: FileEntry; url: string; onDownload: (file: FileEntry) => void }) {
  const [preview, setPreview] = useState<ParquetPreviewData | null>(null);
  const [parseError, setParseError] = useState(false);
  const [parseTimeout, setParseTimeout] = useState(false);
  const [scrollTop, setScrollTop] = useState(0);

  useEffect(() => {
    const timeout = parseTimeoutController();
    setPreview(null);
    setParseError(false);
    setParseTimeout(false);
    setScrollTop(0);

    if ((file.size ?? 0) > PREVIEW_MAX_BYTES) {
      setParseError(true);
      timeout.clear();
      return () => timeout.controller.abort();
    }

    fetch(url, { signal: timeout.controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error("Parquet preview fetch failed");
        return response.arrayBuffer();
      })
      .then(async (buffer) => {
        const source = parquetBufferAdapter(new Uint8Array(buffer));
        const rows = await parquetReadObjects({
          file: source,
          rowFormat: "object",
          rowEnd: PARQUET_PREVIEW_MAX_ROWS + 1,
        });
        setPreview(parseParquetRows(rows));
      })
      .catch((error) => {
        if ((error as Error).name === "AbortError") {
          setParseTimeout(true);
          return;
        }
        setParseError(true);
      })
      .finally(() => {
        timeout.clear();
      });

    return () => {
      timeout.clear();
      timeout.controller.abort();
    };
  }, [file.size, url]);

  if (parseTimeout) {
    return <UnsupportedPreview file={file} onDownload={onDownload} reason="parse_timeout" />;
  }

  if (parseError) {
    return <UnsupportedPreview file={file} onDownload={onDownload} reason="parse_failed" />;
  }

  if (!preview) {
    return <p className="text-sm text-muted-foreground animate-pulse" aria-live="polite">Loading Parquet preview...</p>;
  }

  if (preview.columns.length === 0) {
    return <p className="text-sm text-muted-foreground">Parquet file has no tabular columns to preview.</p>;
  }

  const viewportRows = Math.max(1, Math.ceil(PARQUET_VIEWPORT_HEIGHT_PX / PARQUET_ROW_HEIGHT_PX));
  const startRow = Math.max(0, Math.floor(scrollTop / PARQUET_ROW_HEIGHT_PX) - 6);
  const endRow = Math.min(preview.rows.length, startRow + viewportRows + 12);
  const visibleRows = preview.rows.slice(startRow, endRow);
  const topSpacer = startRow * PARQUET_ROW_HEIGHT_PX;
  const bottomSpacer = Math.max(0, (preview.rows.length - endRow) * PARQUET_ROW_HEIGHT_PX);

  return (
    <div className="flex h-full w-full max-w-6xl flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border bg-muted/30 px-3 py-2 text-xs">
        <span className="text-muted-foreground">Parquet table preview</span>
        <span className="text-muted-foreground">
          Showing {preview.rows.length.toLocaleString()} rows ({preview.columns.length} columns)
        </span>
      </div>

      {(preview.rowTruncated || preview.colTruncated) && (
        <p className="text-xs text-muted-foreground">
          Preview truncated to {PARQUET_PREVIEW_MAX_ROWS.toLocaleString()} rows and {PARQUET_PREVIEW_MAX_COLS} columns.
        </p>
      )}

      <div className="overflow-auto rounded-lg border">
        <table className="w-full border-collapse text-xs">
          <caption className="sr-only">Parquet preview table for {file.name}</caption>
          <thead className="bg-muted/50">
            <tr>
              {preview.columns.map((column, index) => (
                <th key={`pq-h-${index}`} scope="col" className="border-b px-3 py-2 text-left font-medium">
                  {column}
                </th>
              ))}
            </tr>
          </thead>
        </table>

        <div
          className="overflow-auto"
          aria-label="Parquet row viewport"
          style={{ maxHeight: `${PARQUET_VIEWPORT_HEIGHT_PX}px` }}
          onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
        >
          <div style={{ height: `${topSpacer}px` }} />
          <table className="w-full border-collapse text-xs">
            <tbody>
              {visibleRows.map((row, visibleIndex) => {
                const absoluteIndex = startRow + visibleIndex;
                return (
                  <tr
                    key={`pq-r-${absoluteIndex}`}
                    className="odd:bg-background even:bg-muted/20"
                    style={{ height: `${PARQUET_ROW_HEIGHT_PX}px` }}
                  >
                    {row.map((cell, colIndex) => (
                      <td key={`pq-r-${absoluteIndex}-c-${colIndex}`} className="border-b px-3 py-1.5 align-top">
                        {cell}
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
          <div style={{ height: `${bottomSpacer}px` }} />
        </div>
      </div>
    </div>
  );
}

function DocxPreview({ file, url, onDownload }: { file: FileEntry; url: string; onDownload: (file: FileEntry) => void }) {
  const [content, setContent] = useState<string | null>(null);
  const [parseError, setParseError] = useState(false);
  const [parseTimeout, setParseTimeout] = useState(false);

  useEffect(() => {
    const timeout = parseTimeoutController();
    setContent(null);
    setParseError(false);
    setParseTimeout(false);

    if ((file.size ?? 0) > PREVIEW_MAX_BYTES) {
      setParseError(true);
      timeout.clear();
      return () => timeout.controller.abort();
    }

    fetch(url, { signal: timeout.controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error("DOCX preview fetch failed");
        return response.arrayBuffer();
      })
      .then(async (buffer) => {
        const extractRawText = (mammoth as { extractRawText?: (options: { arrayBuffer: ArrayBuffer }) => Promise<{ value: string }>; default?: { extractRawText?: (options: { arrayBuffer: ArrayBuffer }) => Promise<{ value: string }> } }).extractRawText
          ?? (mammoth as { default?: { extractRawText?: (options: { arrayBuffer: ArrayBuffer }) => Promise<{ value: string }> } }).default?.extractRawText;
        if (!extractRawText) {
          const fallbackText = new TextDecoder().decode(new Uint8Array(buffer));
          setContent(fallbackText.trim() || "DOCX preview parser is unavailable in this environment.");
          return;
        }
        const { value } = await extractRawText({ arrayBuffer: buffer });
        if (!value.trim()) {
          setContent("DOCX file has no readable text content.");
          return;
        }
        setContent(value);
      })
      .catch((error) => {
        if ((error as Error).name === "AbortError") {
          setParseTimeout(true);
          return;
        }
        setParseError(true);
      })
      .finally(() => {
        timeout.clear();
      });

    return () => {
      timeout.clear();
      timeout.controller.abort();
    };
  }, [file.size, url]);

  if (parseTimeout) {
    return <UnsupportedPreview file={file} onDownload={onDownload} reason="parse_timeout" />;
  }

  if (parseError) {
    return (
      <div className="w-full max-w-4xl rounded-lg border bg-muted/40 p-4">
        <div className="mb-3 text-xs uppercase tracking-wide text-muted-foreground">DOCX preview</div>
        <p className="text-sm text-muted-foreground">Unable to parse this DOCX in-browser. Download to view the original file.</p>
        <div className="mt-3">
          <Button variant="outline" size="sm" onClick={() => onDownload(file)}>
            <Download className="mr-1 h-3.5 w-3.5" /> Download to view
          </Button>
        </div>
      </div>
    );
  }

  if (content === null) {
    return <p className="text-sm text-muted-foreground animate-pulse" aria-live="polite">Loading DOCX preview...</p>;
  }

  return (
    <div className="w-full max-w-4xl rounded-lg border bg-muted/40 p-4">
      <div className="mb-3 text-xs uppercase tracking-wide text-muted-foreground">DOCX preview</div>
      <pre className="whitespace-pre-wrap break-words text-sm leading-relaxed text-foreground">{content}</pre>
    </div>
  );
}



function PreviewDispatcher({ file, url, onDownload, onForgetRemembered }: { file: FileEntry; url: string; onDownload: (file: FileEntry) => void; onForgetRemembered?: (file: FileEntry) => void; }) {
  const kind = resolvePreviewKind(file);
  const supported = file.preview_supported ?? !file.is_encrypted;
  const reason = file.preview_reason ?? (file.is_encrypted ? "encrypted" : supported ? "none" : "unsupported_type");

  if (file.is_encrypted || !supported) {
    return (
      <div className="flex max-w-md flex-col items-center gap-4 text-center">
        <UnsupportedPreview file={file} onDownload={onDownload} reason={reason} />
        {file.is_encrypted && onForgetRemembered && (
          <Button variant="ghost" size="sm" onClick={() => onForgetRemembered(file)}>
            Forget remembered password for this file
          </Button>
        )}
      </div>
    );
  }

  switch (kind) {
    case "image":
      return <ImagePreview file={file} url={url} onDownload={onDownload} />;
    case "pdf":
      return <PdfPreview file={file} url={url} onDownload={onDownload} />;
    case "text":
      return <TextPreview file={file} url={url} onDownload={onDownload} />;
    case "csv":
      return <CsvTablePreview file={file} url={url} onDownload={onDownload} />;
    case "excel":
      return <ExcelTablePreview file={file} url={url} onDownload={onDownload} />;
    case "parquet":
      return <ParquetTablePreview file={file} url={url} onDownload={onDownload} />;
    case "word":
      if (isDocxFile(file)) {
        return <DocxPreview file={file} url={url} onDownload={onDownload} />;
      }
      if (isLegacyDocFile(file)) {
        return <UnsupportedPreview file={file} onDownload={onDownload} reason="legacy_word_unsupported" />;
      }
      return <UnsupportedPreview file={file} onDownload={onDownload} reason="unsupported_type" />;
    case "none":
    default:
      return <UnsupportedPreview file={file} onDownload={onDownload} reason={reason} />;
  }
}

export function FilePreview({ file, files, onClose, onNavigate, onDownload, onForgetRemembered, previewSrcUrl }: FilePreviewProps) {
  const ct = file.content_type ?? "";
  const url = previewSrcUrl ?? previewUrl(file.path);
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);
  const titleId = `file-preview-title-${file.path}`.replace(/[^a-zA-Z0-9_-]/g, "_");

  // Find index for prev/next
  const filesList = files.filter((f) => f.type === "file");
  const currentIdx = filesList.findIndex((f) => f.path === file.path);
  const prevFile = currentIdx > 0 ? filesList[currentIdx - 1] : undefined;
  const nextFile = currentIdx < filesList.length - 1 ? filesList[currentIdx + 1] : undefined;

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key === "ArrowLeft" && prevFile) onNavigate(prevFile);
      if (e.key === "ArrowRight" && nextFile) onNavigate(nextFile);
    },
    [onClose, onNavigate, prevFile, nextFile],
  );

  useEffect(() => {
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);

  useEffect(() => {
    closeButtonRef.current?.focus();
  }, [file.path]);

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-background/95 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby={titleId}>
      {/* Header */}
      <div className="flex items-center gap-3 border-b px-4 py-3">
        <div className="text-muted-foreground">{fileIcon(ct)}</div>
        <div className="min-w-0 flex-1">
          <p id={titleId} className="truncate text-sm font-medium">{file.name}</p>
          <p className="text-xs text-muted-foreground">
            {ct || "Unknown type"}
            {file.size != null && <span className="ml-2">{formatBytes(file.size)}</span>}
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => onDownload(file)}>
          <Download className="mr-1 h-3.5 w-3.5" />
          Download
        </Button>
        <Button ref={closeButtonRef} variant="ghost" size="icon" onClick={onClose} aria-label="Close preview dialog">
          <X className="h-4 w-4" />
        </Button>
      </div>

      {/* Content */}
      <div className="relative flex-1 overflow-auto">
        {/* Nav arrows */}
        {prevFile && (
          <button
            className="absolute left-2 top-1/2 z-10 flex h-9 w-9 -translate-y-1/2 items-center justify-center rounded-full bg-muted/80 transition-colors hover:bg-muted"
            onClick={() => onNavigate(prevFile)}
            aria-label="Previous file"
          >
            <ChevronLeft className="h-5 w-5" />
          </button>
        )}
        {nextFile && (
          <button
            className="absolute right-2 top-1/2 z-10 flex h-9 w-9 -translate-y-1/2 items-center justify-center rounded-full bg-muted/80 transition-colors hover:bg-muted"
            onClick={() => onNavigate(nextFile)}
            aria-label="Next file"
          >
            <ChevronRight className="h-5 w-5" />
          </button>
        )}

        <div className="flex h-full items-center justify-center p-8">
          <PreviewDispatcher file={file} url={url} onDownload={onDownload} onForgetRemembered={onForgetRemembered} />
        </div>
      </div>

      {/* Footer — file index */}
      {filesList.length > 1 && (
        <div className="border-t px-4 py-2 text-center text-xs text-muted-foreground">
          {currentIdx + 1} of {filesList.length} files
        </div>
      )}
    </div>
  );
}

// ── Text/code preview (escaped text + line numbers + language hints) ──────

type TextLanguage = "plaintext" | "javascript" | "typescript" | "python" | "json" | "html" | "css" | "sql" | "bash";

const TEXT_LANGUAGE_BY_EXTENSION: Record<string, TextLanguage> = {
  js: "javascript",
  cjs: "javascript",
  mjs: "javascript",
  ts: "typescript",
  tsx: "typescript",
  jsx: "javascript",
  py: "python",
  json: "json",
  html: "html",
  htm: "html",
  css: "css",
  scss: "css",
  sql: "sql",
  sh: "bash",
  bash: "bash",
  zsh: "bash",
  yml: "plaintext",
  yaml: "plaintext",
  md: "plaintext",
  txt: "plaintext",
};

function detectTextLanguage(file: FileEntry): TextLanguage {
  const name = file.name.toLowerCase();
  const ext = name.includes(".") ? name.slice(name.lastIndexOf(".") + 1) : "";
  if (ext && TEXT_LANGUAGE_BY_EXTENSION[ext]) return TEXT_LANGUAGE_BY_EXTENSION[ext];

  const mime = (file.content_type ?? "").toLowerCase();
  if (mime.includes("javascript")) return "javascript";
  if (mime.includes("typescript")) return "typescript";
  if (mime.includes("python")) return "python";
  if (mime.includes("json")) return "json";
  if (mime.includes("html")) return "html";
  if (mime.includes("css")) return "css";
  if (mime.includes("sql")) return "sql";
  if (mime.includes("shell") || mime.includes("x-sh")) return "bash";
  return "plaintext";
}

const KEYWORDS: Record<TextLanguage, Set<string>> = {
  plaintext: new Set(),
  javascript: new Set(["const", "let", "var", "function", "return", "if", "else", "for", "while", "class", "new", "import", "from", "export", "async", "await", "try", "catch"]),
  typescript: new Set(["const", "let", "var", "function", "return", "if", "else", "for", "while", "class", "new", "import", "from", "export", "async", "await", "type", "interface", "extends", "implements"]),
  python: new Set(["def", "return", "if", "elif", "else", "for", "while", "class", "import", "from", "as", "try", "except", "with", "lambda", "yield", "None", "True", "False"]),
  json: new Set(["true", "false", "null"]),
  html: new Set(),
  css: new Set(["display", "position", "color", "background", "font", "padding", "margin", "border", "width", "height"]),
  sql: new Set(["SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE", "JOIN", "LEFT", "RIGHT", "INNER", "ORDER", "GROUP", "BY", "LIMIT", "CREATE", "TABLE", "ALTER"]),
  bash: new Set(["if", "then", "else", "fi", "for", "do", "done", "case", "esac", "function", "echo", "export"]),
};

function tokenClass(type: "comment" | "string" | "number" | "keyword" | "plain"): string {
  switch (type) {
    case "comment": return "text-emerald-700";
    case "string": return "text-amber-700";
    case "number": return "text-cyan-700";
    case "keyword": return "text-fuchsia-700 font-medium";
    default: return "text-foreground";
  }
}

function classifyToken(token: string, language: TextLanguage): "comment" | "string" | "number" | "keyword" | "plain" {
  if (/^(#|\/\/|--)/.test(token)) return "comment";
  if ((token.startsWith('"') && token.endsWith('"')) || (token.startsWith("'") && token.endsWith("'")) || (token.startsWith("`") && token.endsWith("`"))) {
    return "string";
  }
  if (/^\d+(?:\.\d+)?$/.test(token)) return "number";
  if (KEYWORDS[language].has(token) || KEYWORDS[language].has(token.toUpperCase())) return "keyword";
  return "plain";
}

function highlightLine(line: string, language: TextLanguage): ReactNode[] {
  if (language === "plaintext") return [line || " "];
  const tokenRegex = /(#.*$|\/\/.*$|--.*$|"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|`(?:\\.|[^`])*`|\d+(?:\.\d+)?|[A-Za-z_][A-Za-z0-9_]*)/g;
  const out: ReactNode[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = tokenRegex.exec(line)) !== null) {
    if (m.index > last) {
      const raw = line.slice(last, m.index);
      out.push(<span key={`p-${last}`}>{raw}</span>);
    }
    const tok = m[0];
    const kind = classifyToken(tok, language);
    out.push(<span key={`t-${m.index}`} className={tokenClass(kind)}>{tok}</span>);
    last = m.index + tok.length;
  }
  if (last < line.length) out.push(<span key={`tail-${last}`}>{line.slice(last)}</span>);
  return out.length ? out : [" "];
}

function TextPreview({ file, url, onDownload }: { file: FileEntry; url: string; onDownload: (file: FileEntry) => void }) {
  const [content, setContent] = useState<string | null>(null);
  const [error, setError] = useState(false);
  const [parseTimeout, setParseTimeout] = useState(false);
  const language = detectTextLanguage(file);

  useEffect(() => {
    const timeout = parseTimeoutController();
    setError(false);
    setParseTimeout(false);

    if ((file.size ?? 0) > PREVIEW_MAX_BYTES) {
      setError(true);
      timeout.clear();
      return () => timeout.controller.abort();
    }

    fetch(url, { signal: timeout.controller.signal })
      .then((r) => {
        if (!r.ok) throw new Error("fetch failed");
        return r.text();
      })
      .then((text) => {
        setContent(text);
      })
      .catch((err) => {
        if ((err as Error).name === "AbortError") {
          setParseTimeout(true);
          return;
        }
        setError(true);
      })
      .finally(() => {
        timeout.clear();
      });

    return () => {
      timeout.clear();
      timeout.controller.abort();
    };
  }, [file.size, url]);

  if (parseTimeout) {
    return <UnsupportedPreview file={file} onDownload={onDownload} reason="parse_timeout" />;
  }

  if (error) {
    return <UnsupportedPreview file={file} onDownload={onDownload} reason={(file.size ?? 0) > PREVIEW_MAX_BYTES ? "too_large" : "parse_failed"} />;
  }

  if (content === null) {
    return <p className="text-sm text-muted-foreground animate-pulse" aria-live="polite">Loading preview...</p>;
  }

  const lines = content.replace(/\r\n/g, "\n").split("\n");
  const lineTruncated = lines.length > TEXT_PREVIEW_MAX_LINES;
  const visibleLines = lines.slice(0, TEXT_PREVIEW_MAX_LINES);

  return (
    <div className="max-h-full w-full max-w-5xl overflow-auto rounded-lg border bg-muted/50">
      <div className="sticky top-0 z-10 border-b bg-muted/80 px-4 py-2 text-[11px] uppercase tracking-wide text-muted-foreground">
        {language}
      </div>
      {lineTruncated && (
        <div className="border-b bg-muted/30 px-4 py-2 text-xs text-muted-foreground">
          Preview truncated to {TEXT_PREVIEW_MAX_LINES.toLocaleString()} lines.
        </div>
      )}
      <pre className="p-0 text-xs leading-relaxed">
        {visibleLines.map((line, idx) => (
          <div key={idx} className="grid grid-cols-[3rem_1fr] gap-0 border-b border-muted/30 last:border-b-0">
            <span className="select-none border-r bg-muted/40 px-2 py-0.5 text-right text-muted-foreground">{idx + 1}</span>
            <code className="whitespace-pre-wrap break-words px-3 py-0.5">{highlightLine(line, language)}</code>
          </div>
        ))}
      </pre>
    </div>
  );
}
