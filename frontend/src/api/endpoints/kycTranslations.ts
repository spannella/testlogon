import { api } from "@/api/client";
import type {
  KycCoverageReport,
  KycLocalizedLegalNotice,
  KycMyLocale,
  KycSupportedLocales,
  KycTranslation,
  KycTranslationBulkImportResult,
  KycTranslationBundle,
  KycTranslationExport,
  KycTranslationList,
} from "@/api/types";

const BASE = "/v1/kyc/i18n";

// ── User-facing ──────────────────────────────────────────────────────

export const getKycSupportedLocales = () =>
  api.get<KycSupportedLocales>(`${BASE}/locales`);

export const getKycTranslationBundle = (language: string, prefix?: string) =>
  api.get<KycTranslationBundle>(
    `${BASE}/translations/${language}`,
    prefix ? { prefix } : undefined,
  );

export const getKycMyLocale = () => api.get<KycMyLocale>(`${BASE}/me/locale`);

export const getKycLegalNotice = (version: string, lang: string) =>
  api.get<KycLocalizedLegalNotice>(`${BASE}/legal-notice/${version}`, { lang });

// ── Admin ────────────────────────────────────────────────────────────

export const adminListKycTranslations = (
  language: string,
  opts?: { prefix?: string; status?: string; limit?: number },
) => {
  const params: Record<string, string> = {};
  if (opts?.prefix) params.prefix = opts.prefix;
  if (opts?.status) params.status = opts.status;
  if (opts?.limit) params.limit = String(opts.limit);
  return api.get<KycTranslationList>(
    `${BASE}/admin/translations/${language}`,
    Object.keys(params).length ? params : undefined,
  );
};

export const adminSetKycTranslation = (
  language: string,
  key: string,
  body: { value: string; context?: string; status?: string },
) => api.put<KycTranslation>(`${BASE}/admin/translations/${language}/${key}`, body);

export const adminDeleteKycTranslation = (language: string, key: string) =>
  api.del<{ ok: boolean }>(`${BASE}/admin/translations/${language}/${key}`);

export const adminGetKycCoverage = () =>
  api.get<KycCoverageReport>(`${BASE}/admin/coverage`);

export const adminBulkImportKycTranslations = (
  language: string,
  body: { translations: Record<string, string>; status?: string },
) =>
  api.post<KycTranslationBulkImportResult>(
    `${BASE}/admin/translations/${language}/bulk-import`,
    body,
  );

export const adminExportKycTranslations = (language: string) =>
  api.get<KycTranslationExport>(`${BASE}/admin/translations/${language}/export`);
