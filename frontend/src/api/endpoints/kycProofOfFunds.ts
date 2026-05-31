import { api } from "@/api/client";

export interface ProofOfFundsSubmission {
  user_sub: string;
  submission_id: string;
  source_category?: string | null;
  declared_amount_cents?: number | null;
  currency?: string | null;
  document_s3_key?: string | null;
  note?: string | null;
  status: string;
  score: number;
  risk_contribution: number;
  created_at: number;
  updated_at: number;
  reviewer_sub?: string | null;
  reviewer_note?: string | null;
  reviewed_at?: number | null;
}

export interface ProofOfFundsSubmissionList {
  submissions: ProofOfFundsSubmission[];
}

export interface ProofOfFundsSummary {
  count: number;
  verified_count: number;
  active_risk_contribution: number;
  verified_amount_cents: number;
  verified_categories: string[];
  user_sub: string;
}

export const kycProofOfFundsApi = {
  createSubmission: (body: {
    source_category?: string | null;
    declared_amount_cents?: number | null;
    currency?: string | null;
    document_s3_key?: string | null;
    note?: string | null;
  }) =>
    api.post<ProofOfFundsSubmission>(
      "/ui/kyc/proof-of-funds/submissions",
      body
    ),

  listMine: () =>
    api.get<ProofOfFundsSubmissionList>("/ui/kyc/proof-of-funds/submissions"),

  summary: () =>
    api.get<ProofOfFundsSummary>("/ui/kyc/proof-of-funds/summary"),

  getOne: (id: string) =>
    api.get<ProofOfFundsSubmission>(
      `/ui/kyc/proof-of-funds/submissions/${id}`
    ),

  listByStatus: (status: string) =>
    api.get<ProofOfFundsSubmissionList>(
      `/ui/kyc/proof-of-funds/review/by-status/${status}`
    ),

  adjudicate: (
    id: string,
    body: { decision: string; reviewer_note?: string | null }
  ) =>
    api.post<ProofOfFundsSubmission>(
      `/ui/kyc/proof-of-funds/review/${id}/adjudicate`,
      body
    ),
};
