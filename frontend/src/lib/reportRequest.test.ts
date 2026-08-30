import { describe, expect, it } from "vitest";

import {
  REPORT_TYPES,
  REPORT_TYPE_META,
  reportTypeLabel,
  reportFormat,
  isClientSideCsv,
  validateReportRequest,
  isValidReportRequest,
  requestPayload,
  reportFilename,
  currentYear,
  type ReportRequest,
} from "./reportRequest";

// A fixed "now" (2024-06-15) so tax-year bounds are deterministic.
const NOW = Date.parse("2024-06-15T12:00:00Z");

describe("catalog", () => {
  it("exposes exactly the four report types", () => {
    expect(REPORT_TYPES).toEqual(["statement", "pnl", "fills", "1099"]);
  });
  it("has meta (label/format/paramsNeeded) for every type", () => {
    for (const t of REPORT_TYPES) {
      const m = REPORT_TYPE_META[t];
      expect(m.type).toBe(t);
      expect(m.label.length).toBeGreaterThan(0);
      expect(["pdf", "csv"]).toContain(m.format);
      expect(Array.isArray(m.paramsNeeded)).toBe(true);
    }
  });
  it("labels the types", () => {
    expect(reportTypeLabel("statement")).toBe("Account statement");
    expect(reportTypeLabel("1099")).toBe("Tax form (1099)");
  });
  it("maps formats: statement/1099 = pdf, fills/pnl = csv", () => {
    expect(reportFormat("statement")).toBe("pdf");
    expect(reportFormat("1099")).toBe("pdf");
    expect(reportFormat("fills")).toBe("csv");
    expect(reportFormat("pnl")).toBe("csv");
  });
  it("marks only fills & pnl as client-side CSV", () => {
    expect(isClientSideCsv("fills")).toBe(true);
    expect(isClientSideCsv("pnl")).toBe(true);
    expect(isClientSideCsv("statement")).toBe(false);
    expect(isClientSideCsv("1099")).toBe(false);
  });
});

describe("validateReportRequest — period types", () => {
  it("statement needs both dates", () => {
    const errs = validateReportRequest({ type: "statement" }, NOW);
    expect(errs.length).toBe(2);
  });
  it("fills accepts a valid period", () => {
    const req: ReportRequest = { type: "fills", periodStart: "2024-01-01", periodEnd: "2024-03-31" };
    expect(validateReportRequest(req, NOW)).toEqual([]);
    expect(isValidReportRequest(req, NOW)).toBe(true);
  });
  it("pnl rejects start > end", () => {
    const errs = validateReportRequest(
      { type: "pnl", periodStart: "2024-04-01", periodEnd: "2024-01-01" },
      NOW,
    );
    expect(errs.some((e) => /on or before/.test(e))).toBe(true);
  });
  it("rejects malformed dates", () => {
    const errs = validateReportRequest(
      { type: "fills", periodStart: "not-a-date", periodEnd: "2024-01-01" },
      NOW,
    );
    expect(errs.some((e) => /start date/i.test(e))).toBe(true);
  });
});

describe("validateReportRequest — 1099", () => {
  it("needs a tax year", () => {
    expect(validateReportRequest({ type: "1099" }, NOW).length).toBe(1);
  });
  it("accepts a plausible year", () => {
    expect(validateReportRequest({ type: "1099", taxYear: 2023 }, NOW)).toEqual([]);
  });
  it("rejects a future year", () => {
    expect(validateReportRequest({ type: "1099", taxYear: 2030 }, NOW).length).toBe(1);
  });
  it("rejects a non-integer year", () => {
    expect(validateReportRequest({ type: "1099", taxYear: 2023.5 }, NOW).length).toBe(1);
  });
  it("does not require a period for 1099", () => {
    expect(isValidReportRequest({ type: "1099", taxYear: 2022 }, NOW)).toBe(true);
  });
});

describe("requestPayload", () => {
  it("statement sends only the period", () => {
    const p = requestPayload({ type: "statement", periodStart: "2024-01-01", periodEnd: "2024-02-01", taxYear: 2024 });
    expect(p).toEqual({ type: "statement", period_start: "2024-01-01", period_end: "2024-02-01" });
    expect(p).not.toHaveProperty("tax_year");
  });
  it("1099 sends only the tax_year (never a period)", () => {
    const p = requestPayload({ type: "1099", taxYear: 2023, periodStart: "2024-01-01" });
    expect(p).toEqual({ type: "1099", tax_year: 2023 });
    expect(p).not.toHaveProperty("period_start");
  });
});

describe("reportFilename", () => {
  it("1099 uses the tax year + pdf ext", () => {
    expect(reportFilename({ type: "1099", taxYear: 2023 })).toBe("testlogon-1099-2023.pdf");
  });
  it("period csv reports use start_end + csv ext", () => {
    expect(reportFilename({ type: "fills", periodStart: "2024-01-01", periodEnd: "2024-03-31" })).toBe(
      "testlogon-fills-2024-01-01_2024-03-31.csv",
    );
  });
  it("statement is a pdf", () => {
    expect(reportFilename({ type: "statement", periodStart: "2024-01-01", periodEnd: "2024-03-31" })).toBe(
      "testlogon-statement-2024-01-01_2024-03-31.pdf",
    );
  });
});

describe("currentYear", () => {
  it("returns the UTC year of the given instant", () => {
    expect(currentYear(NOW)).toBe(2024);
  });
});
