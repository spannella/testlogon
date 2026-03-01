const BASE32_SECRET_PATTERN = /^[A-Z2-7]+=*$/;
const SUPPORTED_ALGORITHMS = new Set(["SHA1", "SHA256", "SHA512"]);
const SUPPORTED_DIGITS = new Set([6, 8]);

type TotpAlgorithm = "SHA1" | "SHA256" | "SHA512";

export interface TotpConfig {
  mode: "otpauth" | "raw";
  secret: string;
  issuer?: string;
  accountName?: string;
  label?: string;
  algorithm: TotpAlgorithm;
  digits: 6 | 8;
  period: number;
}

export interface TotpParseResult {
  ok: boolean;
  config?: TotpConfig;
  errors: string[];
  warnings: string[];
}

const normalizeSecret = (raw: string) => raw.trim().replace(/[\s-]/g, "").toUpperCase();

const validateSecret = (secret: string, errors: string[]) => {
  if (!secret) {
    errors.push("Missing TOTP secret.");
    return;
  }
  if (!BASE32_SECRET_PATTERN.test(secret)) {
    errors.push("TOTP secret must be valid Base32 characters (A-Z and 2-7).");
    return;
  }
  if (secret.length < 16) {
    errors.push("TOTP secret is too short. Expected at least 16 Base32 characters.");
  }
};

const parseSafeInt = (value: string | null) => {
  if (!value) return undefined;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : undefined;
};

export const parseTotpConfigInput = (input: string): TotpParseResult => {
  const errors: string[] = [];
  const warnings: string[] = [];

  const trimmed = input.trim();
  if (!trimmed) {
    return { ok: false, errors: ["Paste an otpauth URI or raw Base32 secret."], warnings };
  }

  if (!trimmed.toLowerCase().startsWith("otpauth://")) {
    const secret = normalizeSecret(trimmed);
    validateSecret(secret, errors);
    if (errors.length > 0) return { ok: false, errors, warnings };

    return {
      ok: true,
      errors,
      warnings,
      config: {
        mode: "raw",
        secret,
        algorithm: "SHA1",
        digits: 6,
        period: 30,
      },
    };
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return { ok: false, errors: ["Invalid otpauth URI format."], warnings };
  }

  const otpType = url.hostname.toLowerCase();
  if (otpType !== "totp") {
    return { ok: false, errors: [`Unsupported OTP type '${otpType}'. Only TOTP is supported.`], warnings };
  }

  const label = decodeURIComponent(url.pathname.replace(/^\//, ""));
  const [labelIssuer, labelAccountName] = label.includes(":") ? label.split(/:(.+)/, 2) : [undefined, label || undefined];

  const secret = normalizeSecret(url.searchParams.get("secret") ?? "");
  validateSecret(secret, errors);

  const issuerParam = url.searchParams.get("issuer")?.trim();
  const issuer = issuerParam || labelIssuer;
  const accountName = labelAccountName;

  const algorithmRaw = (url.searchParams.get("algorithm") || "SHA1").toUpperCase();
  const algorithm = SUPPORTED_ALGORITHMS.has(algorithmRaw) ? (algorithmRaw as TotpAlgorithm) : "SHA1";
  if (!SUPPORTED_ALGORITHMS.has(algorithmRaw)) {
    warnings.push(`Unsupported algorithm '${algorithmRaw}'. Falling back to SHA1.`);
  }

  const parsedDigits = parseSafeInt(url.searchParams.get("digits"));
  const digits = parsedDigits && SUPPORTED_DIGITS.has(parsedDigits) ? (parsedDigits as 6 | 8) : 6;
  if (parsedDigits != null && !SUPPORTED_DIGITS.has(parsedDigits)) {
    warnings.push(`Unsupported digits '${parsedDigits}'. Falling back to 6.`);
  }

  const parsedPeriod = parseSafeInt(url.searchParams.get("period"));
  const period = parsedPeriod && parsedPeriod > 0 ? parsedPeriod : 30;
  if (parsedPeriod != null && parsedPeriod <= 0) {
    warnings.push(`Invalid period '${parsedPeriod}'. Falling back to 30 seconds.`);
  }

  const knownParams = new Set(["secret", "issuer", "algorithm", "digits", "period"]);
  for (const [key] of url.searchParams.entries()) {
    if (!knownParams.has(key)) warnings.push(`Unsupported parameter '${key}' ignored.`);
  }
  if (url.searchParams.has("counter")) {
    warnings.push("HOTP counter parameter is ignored for TOTP.");
  }

  if (errors.length > 0) return { ok: false, errors, warnings };

  return {
    ok: true,
    errors,
    warnings,
    config: {
      mode: "otpauth",
      secret,
      issuer,
      accountName,
      label: label || undefined,
      algorithm,
      digits,
      period,
    },
  };
};
