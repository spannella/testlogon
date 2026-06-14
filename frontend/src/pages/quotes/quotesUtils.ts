import type { QuoteStage, ContractStage } from "@/api/endpoints/quotes";

/** Integer cents -> localized currency string. */
export function formatCents(cents: number | null | undefined, currency = "usd"): string {
  const value = (cents ?? 0) / 100;
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency: (currency || "usd").toUpperCase(),
    }).format(value);
  } catch {
    return `${(currency || "usd").toUpperCase()} ${value.toFixed(2)}`;
  }
}

/** Parse a currency string (e.g. "12.34") into integer cents. Returns 0 on bad input. */
export function parseDollarsToCents(input: string): number {
  const cleaned = input.replace(/[^0-9.]/g, "");
  if (!cleaned) return 0;
  const n = Number.parseFloat(cleaned);
  if (Number.isNaN(n)) return 0;
  return Math.round(n * 100);
}

export function centsToDollarsInput(cents: number | null | undefined): string {
  return ((cents ?? 0) / 100).toFixed(2);
}

export function fmtDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleDateString();
}

export function fmtDateTime(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

/** Convert a `<input type="date">` value (YYYY-MM-DD) to a Unix-seconds timestamp. */
export function dateInputToTs(value: string): number | null {
  if (!value) return null;
  const ms = Date.parse(`${value}T00:00:00`);
  if (Number.isNaN(ms)) return null;
  return Math.floor(ms / 1000);
}

export function tsToDateInput(ts?: number | null): string {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}

// Mirrors ALLOWED_TRANSITIONS in app/services/aos_quotes.py
export const QUOTE_TRANSITIONS: Record<QuoteStage, QuoteStage[]> = {
  draft: ["sent", "expired"],
  sent: ["accepted", "rejected", "expired"],
  accepted: ["converted", "expired"],
  rejected: [],
  expired: [],
  converted: [],
};

// Mirrors _ALLOWED_TRANSITIONS in app/services/aos_contracts.py
export const CONTRACT_TRANSITIONS: Record<ContractStage, ContractStage[]> = {
  draft: ["active"],
  active: ["expired", "terminated", "renewed"],
  expired: [],
  terminated: [],
  renewed: [],
};

export const QUOTE_STAGES: QuoteStage[] = [
  "draft",
  "sent",
  "accepted",
  "rejected",
  "expired",
  "converted",
];

export const CONTRACT_STAGES: ContractStage[] = [
  "draft",
  "active",
  "expired",
  "terminated",
  "renewed",
];

export function quoteStageVariant(
  stage: QuoteStage,
): "default" | "secondary" | "destructive" | "outline" {
  switch (stage) {
    case "accepted":
    case "converted":
      return "default";
    case "rejected":
    case "expired":
      return "destructive";
    case "sent":
      return "secondary";
    default:
      return "outline";
  }
}

export function contractStageVariant(
  stage: ContractStage,
): "default" | "secondary" | "destructive" | "outline" {
  switch (stage) {
    case "active":
    case "renewed":
      return "default";
    case "expired":
    case "terminated":
      return "destructive";
    default:
      return "outline";
  }
}

/** Detect the "feature not enabled" backend response (flag off -> 404/503). */
export function isNotEnabled(err: unknown): boolean {
  const status = (err as { status?: number } | null)?.status;
  return status === 404 || status === 503;
}
