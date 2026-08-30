// FE-171 (EPIC H) — "Statements & reports" request/download section for the
// Export & reporting screen. Pick a report type + the params it needs, then
// Generate/Download:
//   - fills / pnl (CSV): built ENTIRELY client-side from the live fills the
//     parent already loaded (a guaranteed real download) via exportReport.ts.
//   - statement / 1099 (PDF): requested from the backend (BE-170); on success we
//     point the user at Trading Documents; on 404 we degrade to an honest
//     "not available yet" message. No crash either way.
// All validation is done by the pure reportRequest.ts lib before submit.
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { FileText, Download, Loader2, Info } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { requestTradingDocument } from "@/api/endpoints/tradingDocuments";
import {
  buildTradeHistoryCsv,
  buildPnlSummaryCsv,
  downloadCsv,
  type ReportFill,
  type SymbolResolver,
} from "@/lib/exportReport";
import type { PnlSummary } from "@/lib/pnl";
import {
  REPORT_TYPES,
  REPORT_TYPE_META,
  isClientSideCsv,
  validateReportRequest,
  requestPayload,
  reportFilename,
  reportTypeLabel,
  currentYear,
  type ReportType,
  type ReportRequest,
} from "@/lib/reportRequest";

export interface StatementsReportsCardProps {
  /** ALL fills (unscoped) — the section filters them to the chosen period. */
  fills: ReportFill[];
  /** symbolid -> {name, scaler}. */
  resolve: SymbolResolver;
  /** Quote-asset scaler for the aggregate P&L TOTAL row. */
  quoteScaler: number;
  /** True when the fills feed is unavailable (CSV reports cannot be built). */
  fillsUnavailable?: boolean;
}

const MS_THRESHOLD = 1e12;
const toMs = (ts: number): number => (ts < MS_THRESHOLD ? ts * 1000 : ts);

/** Inclusive [start,end] filter over fills by ISO date (end = end-of-day). */
function scopeFills(fills: ReportFill[], startIso: string, endIso: string): ReportFill[] {
  const start = Date.parse(startIso + "T00:00:00Z");
  const end = Date.parse(endIso + "T23:59:59Z");
  if (Number.isNaN(start) || Number.isNaN(end)) return fills;
  return fills.filter((f) => {
    const ms = toMs(f.ts);
    return ms >= start && ms <= end;
  });
}

// Default period: start of this year -> today.
function defaultStart(): string {
  const d = new Date();
  return `${d.getUTCFullYear()}-01-01`;
}
function today(): string {
  return new Date().toISOString().slice(0, 10);
}

export default function StatementsReportsCard({
  fills,
  resolve,
  quoteScaler,
  fillsUnavailable,
}: StatementsReportsCardProps) {
  const [type, setType] = useState<ReportType>("statement");
  const [periodStart, setPeriodStart] = useState<string>(defaultStart());
  const [periodEnd, setPeriodEnd] = useState<string>(today());
  const [taxYear, setTaxYear] = useState<number>(currentYear() - 1);
  const [submitting, setSubmitting] = useState(false);
  const [unavailableMsg, setUnavailableMsg] = useState<string | null>(null);

  const meta = REPORT_TYPE_META[type];
  const needsPeriod = meta.paramsNeeded.includes("period");
  const needsTaxYear = meta.paramsNeeded.includes("taxYear");
  const clientSide = isClientSideCsv(type);

  const req: ReportRequest = useMemo(
    () => ({
      type,
      periodStart: needsPeriod ? periodStart : undefined,
      periodEnd: needsPeriod ? periodEnd : undefined,
      taxYear: needsTaxYear ? taxYear : undefined,
    }),
    [type, needsPeriod, periodStart, periodEnd, needsTaxYear, taxYear],
  );

  const errors = useMemo(() => validateReportRequest(req), [req]);
  const valid = errors.length === 0;

  // Tax-year options: last 6 years up to current.
  const taxYears = useMemo(() => {
    const cur = currentYear();
    return Array.from({ length: 6 }, (_, i) => cur - i);
  }, []);

  const clientSideUnavailable = clientSide && fillsUnavailable;

  async function onGenerate() {
    setUnavailableMsg(null);
    if (!valid) {
      toast.error(errors[0]);
      return;
    }

    // fills / pnl -> build the CSV client-side from the scoped live fills.
    if (clientSide) {
      if (fillsUnavailable) {
        toast.error("Trade history is not available on this backend yet.");
        return;
      }
      const scoped = scopeFills(fills, periodStart, periodEnd);
      if (scoped.length === 0) {
        toast.error("No trades in the selected period. Pick a wider range.");
        return;
      }
      const filename = reportFilename(req);
      if (type === "fills") {
        downloadCsv(filename, buildTradeHistoryCsv(scoped, resolve));
      } else {
        // pnl - compute a summary over the scoped fills only.
        const { computePnl } = await import("@/lib/pnl");
        const summary: PnlSummary = computePnl(
          scoped.map((f) => ({
            symbolid: f.symbolid,
            price: f.price,
            qty: f.qty,
            side: f.side === "sell" ? "sell" : "buy",
            fee: f.fee,
            ts: f.ts,
          })),
          [],
          [],
        );
        downloadCsv(filename, buildPnlSummaryCsv(summary.perSymbol, summary, resolve, quoteScaler));
      }
      toast.success(`Downloaded ${filename}`);
      return;
    }

    // statement / 1099 (PDF) -> request backend generation (BE-170).
    setSubmitting(true);
    try {
      const result = await requestTradingDocument(requestPayload(req));
      if (result.accepted) {
        toast.success(
          `${reportTypeLabel(type)} is generating — it will appear in Trading Documents when ready.`,
        );
      } else {
        setUnavailableMsg(
          `${reportTypeLabel(type)} generation is not available on this backend yet. It will appear in Trading Documents once the reporting service is deployed.`,
        );
      }
    } catch {
      toast.error(`Could not request your ${reportTypeLabel(type).toLowerCase()}. Please try again.`);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          <FileText className="h-4 w-4 text-muted-foreground" />
          Statements &amp; reports
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-xs text-muted-foreground">{meta.description}</p>

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {/* type */}
          <div className="flex flex-col gap-1.5">
            <Label className="text-xs" htmlFor="report-type">
              Report
            </Label>
            <Select value={type} onValueChange={(v) => setType(v as ReportType)}>
              <SelectTrigger id="report-type" className="h-9" aria-label="Report type">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {REPORT_TYPES.map((t) => (
                  <SelectItem key={t} value={t}>
                    {reportTypeLabel(t)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* period */}
          {needsPeriod && (
            <>
              <div className="flex flex-col gap-1.5">
                <Label className="text-xs" htmlFor="report-from">
                  From
                </Label>
                <Input
                  id="report-from"
                  type="date"
                  value={periodStart}
                  max={periodEnd || undefined}
                  onChange={(e) => setPeriodStart(e.target.value)}
                  className="h-9"
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label className="text-xs" htmlFor="report-to">
                  To
                </Label>
                <Input
                  id="report-to"
                  type="date"
                  value={periodEnd}
                  min={periodStart || undefined}
                  onChange={(e) => setPeriodEnd(e.target.value)}
                  className="h-9"
                />
              </div>
            </>
          )}

          {/* tax year */}
          {needsTaxYear && (
            <div className="flex flex-col gap-1.5">
              <Label className="text-xs" htmlFor="report-year">
                Tax year
              </Label>
              <Select value={String(taxYear)} onValueChange={(v) => setTaxYear(Number(v))}>
                <SelectTrigger id="report-year" className="h-9" aria-label="Tax year">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {taxYears.map((y) => (
                    <SelectItem key={y} value={String(y)}>
                      {y}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          {/* action */}
          <div className="flex items-end">
            <Button
              type="button"
              className="h-9 w-full gap-1.5"
              onClick={onGenerate}
              disabled={submitting || !valid || clientSideUnavailable}
            >
              {submitting ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Download className="h-4 w-4" />
              )}
              {clientSide ? "Download CSV" : "Generate"}
            </Button>
          </div>
        </div>

        {!valid && <p className="text-xs text-destructive">{errors[0]}</p>}

        {clientSideUnavailable && (
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription className="text-xs">
              Trade history is not available on this backend yet, so this CSV cannot be built.
            </AlertDescription>
          </Alert>
        )}

        {unavailableMsg && (
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription className="text-xs">{unavailableMsg}</AlertDescription>
          </Alert>
        )}

        <p className="text-[11px] text-muted-foreground">
          CSV reports (fills &amp; P&amp;L) download immediately. PDF documents (statements &amp;
          1099) are generated in the background and appear in{" "}
          <Link to="/files/trading-documents" className="underline">
            Trading Documents
          </Link>
          .
        </p>
      </CardContent>
    </Card>
  );
}
