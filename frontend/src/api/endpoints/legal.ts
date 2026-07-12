import { api, withApiBase } from "@/api/client";
import type {
  LegalHold,
  PlaceHoldBody,
  LegalExport,
  LegalExportIntakeBody,
} from "@/api/types";

// ─── Legal holds (LEX-008) ──────────────────────────────────────

export const placeLegalHold = (body: PlaceHoldBody) =>
  api.post<LegalHold>("/ui/legal/holds", body);

export const listLegalHolds = () =>
  api.get<LegalHold[]>("/ui/legal/holds");

export const getLegalHold = (holdId: string) =>
  api.get<LegalHold>(`/ui/legal/holds/${holdId}`);

export const releaseLegalHold = (holdId: string) =>
  api.post<LegalHold>(`/ui/legal/holds/${holdId}/release`);

// ─── Legal exports (LEX-012) ────────────────────────────────────

export const createLegalExport = (body: LegalExportIntakeBody) =>
  api.post<LegalExport>("/ui/legal/exports", body);

export const generateLegalExport = (legalExportId: string) =>
  api.post<LegalExport>(`/ui/legal/exports/${legalExportId}/generate`);

export const listLegalExports = () =>
  api.get<LegalExport[]>("/ui/legal/exports");

export const getLegalExport = (legalExportId: string) =>
  api.get<LegalExport>(`/ui/legal/exports/${legalExportId}`);

/** The download endpoint 302-redirects to a short-lived presigned URL. Open
 * directly in a new tab so the browser follows the redirect. */
export const getLegalExportDownloadUrl = (legalExportId: string) =>
  withApiBase(`/ui/legal/exports/${legalExportId}/download`);
