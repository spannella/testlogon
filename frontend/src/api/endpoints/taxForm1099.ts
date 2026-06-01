import { api } from "@/api/client";
import type {
  TaxForm1099,
  TaxForm1099List,
  TaxForm1099Download,
  BatchGenerateTaxForm1099Result,
} from "@/api/types";

// ── Creator-scoped (FIN-008) ────────────────────────────────────────────────

export const listMy1099s = () =>
  api.get<TaxForm1099List>("/ui/tax-forms/1099s");

export const getMy1099 = (taxYear: number) =>
  api.get<TaxForm1099>(`/ui/tax-forms/1099s/${taxYear}`);

export const generateMy1099 = (taxYear: number) =>
  api.post<TaxForm1099>(`/ui/tax-forms/1099s/${taxYear}/generate`);

export const downloadMy1099 = (taxYear: number) =>
  api.get<TaxForm1099Download>(`/ui/tax-forms/1099s/${taxYear}/download`);

// ── Admin (FIN-008) ─────────────────────────────────────────────────────────

export const adminGenerate1099 = (taxYear: number, userSub: string) =>
  api.post<TaxForm1099>(
    `/ui/tax-forms/admin/1099s/${taxYear}/generate`,
    undefined,
    { user_sub: userSub },
  );

export const adminCorrect1099 = (taxYear: number, userSub: string) =>
  api.post<TaxForm1099>(
    `/ui/tax-forms/admin/1099s/${taxYear}/correct`,
    undefined,
    { user_sub: userSub },
  );

export const adminBatchGenerate1099s = (taxYear: number) =>
  api.post<BatchGenerateTaxForm1099Result>("/ui/tax-forms/admin/batch", {
    tax_year: taxYear,
  });

export const adminListYear1099s = (taxYear: number) =>
  api.get<TaxForm1099List>(`/ui/tax-forms/admin/year/${taxYear}`);
