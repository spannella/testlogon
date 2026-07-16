import { useState } from "react";
import {
  kycProofOfFundsApi,
  ProofOfFundsSubmission,
} from "@/api/endpoints/kycProofOfFunds";

const SOURCE_CATEGORIES = [
  "bank_statement",
  "pay_stub",
  "sale_of_asset",
  "investment",
  "business_income",
  "inheritance",
  "gift",
  "savings",
];

const REVIEW_STATUSES = [
  "pending",
  "verified",
  "rejected",
  "needs_more_info",
  "expired",
];

function statusClass(status: string): string {
  switch (status) {
    case "verified":
      return "bg-green-100 text-green-800";
    case "rejected":
      return "bg-red-100 text-red-800";
    case "needs_more_info":
      return "bg-yellow-100 text-yellow-800";
    case "expired":
      return "bg-gray-200 text-gray-700";
    default:
      return "bg-blue-100 text-blue-800";
  }
}

function formatAmount(cents?: number | null, currency?: string | null): string {
  if (cents === null || cents === undefined) return "—";
  return `${(cents / 100).toFixed(2)} ${currency || "USD"}`;
}

export default function KycProofOfFunds() {
  const [sourceCategory, setSourceCategory] = useState(SOURCE_CATEGORIES[0]);
  const [declaredAmount, setDeclaredAmount] = useState("");
  const [documentKey, setDocumentKey] = useState("");
  const [note, setNote] = useState("");
  const [submissions, setSubmissions] = useState<ProofOfFundsSubmission[]>([]);

  const [reviewStatus, setReviewStatus] = useState("pending");
  const [reviewItems, setReviewItems] = useState<ProofOfFundsSubmission[]>([]);

  async function refresh() {
    const res = await kycProofOfFundsApi.listMine();
    setSubmissions(res.submissions);
  }

  async function submit() {
    const amountCents =
      declaredAmount.trim() === ""
        ? undefined
        : Math.round(parseFloat(declaredAmount) * 100);
    await kycProofOfFundsApi.createSubmission({
      source_category: sourceCategory,
      declared_amount_cents: amountCents,
      currency: "USD",
      document_s3_key: documentKey || undefined,
      note: note || undefined,
    });
    setDeclaredAmount("");
    setDocumentKey("");
    setNote("");
    await refresh();
  }

  async function loadReview() {
    const res = await kycProofOfFundsApi.listByStatus(reviewStatus);
    setReviewItems(res.submissions);
  }

  async function adjudicate(id: string, decision: string) {
    await kycProofOfFundsApi.adjudicate(id, { decision, reviewer_note: decision });
    await loadReview();
  }

  return (
    <div className="p-6 space-y-8">
      <div>
        <h1 className="text-2xl font-semibold">Proof of Funds</h1>
        <p className="text-sm text-muted-foreground">
          Submit documentation showing the source of your funds.
        </p>
      </div>

      <div className="space-y-3 max-w-md">
        <div>
          <label className="text-sm font-medium">Source category</label>
          <select
            className="w-full border rounded px-3 py-2"
            value={sourceCategory}
            onChange={(e) => setSourceCategory(e.target.value)}
          >
            {SOURCE_CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="text-sm font-medium">Declared amount</label>
          <input
            className="w-full border rounded px-3 py-2"
            type="number"
            placeholder="0.00"
            value={declaredAmount}
            onChange={(e) => setDeclaredAmount(e.target.value)}
          />
        </div>
        <div>
          <label className="text-sm font-medium">Document key (optional)</label>
          <input
            className="w-full border rounded px-3 py-2"
            value={documentKey}
            onChange={(e) => setDocumentKey(e.target.value)}
          />
        </div>
        <div>
          <label className="text-sm font-medium">Note</label>
          <textarea
            className="w-full border rounded px-3 py-2"
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
        </div>
        <button
          className="bg-primary text-white rounded px-4 py-2"
          onClick={submit}
        >
          Submit
        </button>
      </div>

      <div className="space-y-2">
        <h2 className="text-lg font-medium">My submissions</h2>
        {submissions.length === 0 && (
          <div className="text-sm text-muted-foreground">No submissions yet.</div>
        )}
        {submissions.map((s) => (
          <div
            key={s.submission_id}
            className="border rounded p-3 flex justify-between items-center"
          >
            <div>
              <div className="font-medium">{s.source_category}</div>
              <div className="text-sm text-muted-foreground">
                {formatAmount(s.declared_amount_cents, s.currency)}
              </div>
            </div>
            <span
              className={`text-xs rounded px-2 py-1 ${statusClass(s.status)}`}
            >
              {s.status}
            </span>
          </div>
        ))}
      </div>

      <div className="space-y-3">
        <h2 className="text-lg font-medium">Reviewer queue</h2>
        <div className="flex gap-2 items-center">
          <select
            className="border rounded px-3 py-2"
            value={reviewStatus}
            onChange={(e) => setReviewStatus(e.target.value)}
          >
            {REVIEW_STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <button
            className="border rounded px-4 py-2"
            onClick={loadReview}
          >
            Load
          </button>
        </div>
        {reviewItems.map((s) => (
          <div
            key={s.submission_id}
            className="border rounded p-3 flex justify-between items-center"
          >
            <div>
              <div className="font-medium">{s.source_category}</div>
              <div className="text-sm text-muted-foreground">
                {s.user_sub} · score {s.score}
              </div>
            </div>
            <div className="flex gap-2">
              <button
                className="text-xs rounded px-2 py-1 bg-green-100 text-green-800"
                onClick={() => adjudicate(s.submission_id, "verified")}
              >
                Verify
              </button>
              <button
                className="text-xs rounded px-2 py-1 bg-yellow-100 text-yellow-800"
                onClick={() => adjudicate(s.submission_id, "needs_more_info")}
              >
                More info
              </button>
              <button
                className="text-xs rounded px-2 py-1 bg-red-100 text-red-800"
                onClick={() => adjudicate(s.submission_id, "rejected")}
              >
                Reject
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
