// Card-network (issuer) detection by card number — IIN/BIN prefix based.
// Used by the add-card form to recognize Visa / Mastercard / Amex / Discover /
// ATH and fall back to "other".

export type CardNetworkId =
  | "visa"
  | "mastercard"
  | "amex"
  | "discover"
  | "ath"
  | "other";

export interface CardNetwork {
  id: CardNetworkId;
  label: string;
}

const LABELS: Record<CardNetworkId, string> = {
  visa: "Visa",
  mastercard: "Mastercard",
  amex: "Amex",
  discover: "Discover",
  ath: "ATH",
  other: "Card",
};

// ATH (A Toda Hora — Puerto Rico's interbank debit network) issuer BIN prefixes.
// NOTE: ATH cards are frequently co-branded on Visa/Mastercard rails, so detecting
// "ATH" purely from the number is best-effort. Populate with the issuer BIN ranges
// you want treated as ATH; checked BEFORE Visa/MC so co-branded numbers resolve to
// ATH. Empty by default (no false positives) — add known prefixes here.
const ATH_PREFIXES: string[] = [
  // e.g. "458045", "542418" — confirm against issuer BIN list
];

function startsWithAny(num: string, prefixes: string[]): boolean {
  return prefixes.some((p) => p && num.startsWith(p));
}

/** Detect the card network from a (possibly formatted) card number. */
export function detectCardNetwork(raw: string): CardNetwork {
  const n = (raw || "").replace(/\D/g, "");
  if (!n) return { id: "other", label: LABELS.other };

  // ATH first: co-branded numbers would otherwise match Visa/Mastercard.
  if (startsWithAny(n, ATH_PREFIXES)) return { id: "ath", label: LABELS.ath };

  // Visa: starts with 4
  if (/^4/.test(n)) return { id: "visa", label: LABELS.visa };
  // Amex: 34, 37
  if (/^3[47]/.test(n)) return { id: "amex", label: LABELS.amex };
  // Mastercard: 51–55, and 2221–2720
  if (/^(5[1-5]|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)/.test(n)) {
    return { id: "mastercard", label: LABELS.mastercard };
  }
  // Discover: 6011, 65, 644–649, 622126–622925
  if (/^(6011|65|64[4-9]|622(12[6-9]|1[3-9]\d|[2-8]\d{2}|9[01]\d|92[0-5]))/.test(n)) {
    return { id: "discover", label: LABELS.discover };
  }
  return { id: "other", label: LABELS.other };
}

/** Luhn checksum — true if the number could be valid. */
export function luhnValid(raw: string): boolean {
  const n = (raw || "").replace(/\D/g, "");
  if (n.length < 12) return false;
  let sum = 0;
  let dbl = false;
  for (let i = n.length - 1; i >= 0; i--) {
    let d = n.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

/** Group digits for display: Amex as 4-6-5, everyone else as 4-4-4-4(-…). */
export function formatCardNumber(raw: string, network?: CardNetworkId): string {
  const n = (raw || "").replace(/\D/g, "").slice(0, 19);
  const id = network ?? detectCardNetwork(n).id;
  const groups = id === "amex" ? [4, 6, 5] : [4, 4, 4, 4, 4];
  const out: string[] = [];
  let i = 0;
  for (const g of groups) {
    if (i >= n.length) break;
    out.push(n.slice(i, i + g));
    i += g;
  }
  if (i < n.length) out.push(n.slice(i));
  return out.join(" ");
}
