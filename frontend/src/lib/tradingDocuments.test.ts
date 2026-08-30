import { describe, it, expect } from "vitest";
import type { TradingDocument } from "@/api/endpoints/tradingDocuments";
import {
  TRADING_DOC_TYPES,
  TRADING_DOC_ICONS,
  docTypeLabel,
  groupDocuments,
  docTitle,
  docFilename,
  isDownloadable,
  formatBytes,
  formatDocMeta,
} from "./tradingDocuments";

function doc(over: Partial<TradingDocument>): TradingDocument {
  return { doc_id: "d1", type: "statement", ...over };
}

describe("catalog", () => {
  it("has a label + icon key for every type", () => {
    for (const t of TRADING_DOC_TYPES) {
      expect(docTypeLabel(t)).toBeTruthy();
      expect(TRADING_DOC_ICONS[t]).toBeTruthy();
    }
  });

  it("titleises unknown types", () => {
    expect(docTypeLabel("trade_confirmation")).toBe("Trade Confirmation");
  });
});

describe("docTitle", () => {
  it("prefers an explicit title", () => {
    expect(docTitle(doc({ title: "Custom Name" }))).toBe("Custom Name");
  });

  it("builds a statement title from tax_year", () => {
    expect(docTitle(doc({ type: "statement", tax_year: 2024 }))).toBe("2024 Account Statement");
  });

  it("builds a 1099 title", () => {
    expect(docTitle(doc({ type: "1099", tax_year: 2024 }))).toBe("1099-B 2024");
  });

  it("builds a confirmation title from period_start", () => {
    expect(docTitle(doc({ type: "confirmation", period_start: "2024-06-01" }))).toBe(
      "Trade Confirmation — 2024-06-01",
    );
  });

  it("derives the year from period_start when no tax_year", () => {
    expect(docTitle(doc({ type: "pnl", period_start: "2023-01-01" }))).toBe("2023 P&L Statement");
  });
});

describe("docFilename", () => {
  it("uses the csv extension for csv docs", () => {
    expect(docFilename(doc({ type: "fills", tax_year: 2024, format: "csv" }))).toBe(
      "2024-fills-report.csv",
    );
  });

  it("defaults to pdf and is filesystem-safe", () => {
    const name = docFilename(doc({ type: "confirmation", period_start: "2024-06-01" }));
    expect(name).toBe("trade-confirmation-2024-06-01.pdf");
    expect(name).not.toMatch(/[^a-z0-9.\-]/);
  });
});

describe("isDownloadable", () => {
  it("false while generating", () => {
    expect(isDownloadable(doc({ status: "generating", download_url: "x" }))).toBe(false);
  });

  it("true when ready with a doc_id", () => {
    expect(isDownloadable(doc({ status: "ready" }))).toBe(true);
  });

  it("true when a download_url is present", () => {
    expect(isDownloadable(doc({ download_url: "https://x/y.pdf" }))).toBe(true);
  });
});

describe("formatBytes", () => {
  it("formats small + large sizes", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5 MB");
  });

  it("returns empty for missing/invalid", () => {
    expect(formatBytes(undefined)).toBe("");
    expect(formatBytes(-1)).toBe("");
  });
});

describe("formatDocMeta", () => {
  it("joins period, size and format without dangling separators", () => {
    const meta = formatDocMeta(
      doc({ period_start: "2024-01-01", period_end: "2024-12-31", size_bytes: 2048, format: "pdf" }),
    );
    expect(meta).toBe("2024-01-01 – 2024-12-31 · 2 KB · PDF");
  });

  it("falls back to created_at when no period", () => {
    expect(formatDocMeta(doc({ created_at: "2024-06-01" }))).toBe("2024-06-01");
  });

  it("is empty when nothing is known", () => {
    expect(formatDocMeta(doc({}))).toBe("");
  });
});

describe("groupDocuments", () => {
  it("groups by type in catalog order, newest-first within a group", () => {
    const docs: TradingDocument[] = [
      doc({ doc_id: "a", type: "1099", created_at: "2024-01-01" }),
      doc({ doc_id: "b", type: "statement", created_at: "2023-01-01" }),
      doc({ doc_id: "c", type: "statement", created_at: "2024-01-01" }),
    ];
    const groups = groupDocuments(docs);
    expect(groups.map((g) => g.type)).toEqual(["statement", "1099"]);
    expect(groups[0]?.documents.map((d) => d.doc_id)).toEqual(["c", "b"]);
  });

  it("places unknown types after known ones and omits empty groups", () => {
    const docs: TradingDocument[] = [
      doc({ doc_id: "x", type: "custom" as TradingDocument["type"] }),
      doc({ doc_id: "y", type: "pnl" }),
    ];
    const groups = groupDocuments(docs);
    expect(groups.map((g) => g.type)).toEqual(["pnl", "custom"]);
  });

  it("returns [] for no docs", () => {
    expect(groupDocuments([])).toEqual([]);
  });
});
