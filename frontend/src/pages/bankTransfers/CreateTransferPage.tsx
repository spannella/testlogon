/**
 * CreateTransferPage — TXR-001 + TXR-003 + TXR-004
 *
 * Step 1: Build and submit a transaction request.
 * Step 2: If SCA is required (status=PENDING), show ScaChallengePanel.
 * Step 3: Execute the authorised request to move money.
 *
 * Route: /bank/transfers/new
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ArrowLeftRight,
  Loader2,
  AlertCircle,
  CheckCircle2,
  ChevronLeft,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import {
  createTxnRequest,
  executeTxnRequest,
  type TxnRequestOut,
  type TxnRequestType,
} from "@/api/endpoints/txnRequests";
import { ApiError } from "@/api/client";

import { ScaChallengePanel } from "./ScaChallengePanel";
import {
  formatCurrency,
  STATUS_BADGE,
  STATUS_LABEL,
  TXN_TYPES,
} from "./txrUtils";

// ─── Currency options ─────────────────────────────────────────────────────────

const CURRENCIES = ["usd", "eur", "gbp", "cad", "aud"];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function buildTarget(type: TxnRequestType, fields: Record<string, string>): Record<string, unknown> {
  switch (type) {
    case "WALLET_TRANSFER":
      return { to_user_sub: fields["to_user_sub"] ?? "" };
    case "FREE_FORM":
      return fields["to_user_sub"] ? { to_user_sub: fields["to_user_sub"] } : {};
    case "PAYOUT":
      return { payout_method_id: fields["payout_method_id"] ?? "" };
    case "REFUND":
      return { payment_intent_id: fields["payment_intent_id"] ?? "" };
    case "COUNTERPARTY":
      return { counterparty_ref: fields["counterparty_ref"] ?? "" };
  }
}

// ─── Component ────────────────────────────────────────────────────────────────

type Step = "form" | "sca" | "execute" | "done" | "error";

export default function CreateTransferPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // Form state
  const [type, setType] = useState<TxnRequestType>("WALLET_TRANSFER");
  const [amountStr, setAmountStr] = useState("");
  const [currency, setCurrency] = useState("usd");
  const [reason, setReason] = useState("");
  const [targetFields, setTargetFields] = useState<Record<string, string>>({});

  // Flow state
  const [step, setStep] = useState<Step>("form");
  const [submitting, setSubmitting] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [txnRequest, setTxnRequest] = useState<TxnRequestOut | null>(null);
  const [errorMsg, setErrorMsg] = useState("");

  function setField(key: string, value: string) {
    setTargetFields((prev) => ({ ...prev, [key]: value }));
  }

  // ── Step 1: Create ────────────────────────────────────────────────────────

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    const amountCents = Math.round(parseFloat(amountStr) * 100);
    if (!amountStr || isNaN(amountCents) || amountCents <= 0) {
      toast.error("Enter a valid amount greater than zero");
      return;
    }

    setSubmitting(true);
    setErrorMsg("");
    try {
      const result = await createTxnRequest({
        type,
        amount_cents: amountCents,
        currency,
        target: buildTarget(type, targetFields),
        reason: reason.trim() || undefined,
      });
      setTxnRequest(result);
      queryClient.invalidateQueries({ queryKey: ["txnRequests"] });

      if (result.status === "PENDING" && result.sca_challenge_id) {
        setStep("sca");
      } else if (result.status === "INITIATED") {
        setStep("execute");
      } else {
        setStep("done");
      }
    } catch (err) {
      const msg = err instanceof ApiError ? err.detail : "Failed to create transfer";
      if (err instanceof ApiError && err.status === 404) {
        setErrorMsg("Transaction requests are not enabled on this platform.");
      } else {
        setErrorMsg(msg);
      }
      setStep("error");
    } finally {
      setSubmitting(false);
    }
  }

  // ── Step 2 → 3: SCA complete → Execute ───────────────────────────────────

  async function handleScaComplete() {
    if (!txnRequest) return;
    await handleExecute(txnRequest.request_id);
  }

  // ── Step 3: Execute ───────────────────────────────────────────────────────

  async function handleExecute(requestId: string) {
    setExecuting(true);
    setErrorMsg("");
    try {
      const result = await executeTxnRequest(requestId);
      setTxnRequest(result);
      queryClient.invalidateQueries({ queryKey: ["txnRequests"] });
      setStep("done");
      toast.success("Transfer completed successfully");
    } catch (err) {
      const msg = err instanceof ApiError ? err.detail : "Execution failed";
      setErrorMsg(msg);
      // Refresh the request to reflect FAILED state
      if (txnRequest) {
        try {
          const refreshed = await import("@/api/endpoints/txnRequests").then((m) =>
            m.getTxnRequest(requestId)
          );
          setTxnRequest(refreshed);
        } catch {
          // best-effort refresh
        }
      }
      setStep("error");
    } finally {
      setExecuting(false);
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────

  const selectedTypeInfo = TXN_TYPES.find((t) => t.value === type);

  return (
    <div className="space-y-6 p-4 sm:p-6 max-w-2xl">
      <PageHeader
        title="New Transfer"
        description="Send funds or initiate a transaction request"
        actions={
          <Button variant="ghost" size="sm" onClick={() => navigate("/bank/transfers")}>
            <ChevronLeft className="mr-1 h-4 w-4" />
            Back to Transfers
          </Button>
        }
      />

      {/* ── FORM STEP ── */}
      {step === "form" && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ArrowLeftRight className="h-5 w-5 text-muted-foreground" />
              Transfer Details
            </CardTitle>
            <CardDescription>
              Fill in the details below. High-value transfers may require additional
              identity verification (SCA).
            </CardDescription>
          </CardHeader>

          <CardContent>
            <form onSubmit={handleCreate} className="space-y-5">
              {/* Type */}
              <div className="space-y-1.5">
                <Label htmlFor="type">Transfer type</Label>
                <Select
                  value={type}
                  onValueChange={(v) => {
                    setType(v as TxnRequestType);
                    setTargetFields({});
                  }}
                >
                  <SelectTrigger id="type">
                    <SelectValue placeholder="Select type" />
                  </SelectTrigger>
                  <SelectContent>
                    {TXN_TYPES.map((t) => (
                      <SelectItem key={t.value} value={t.value}>
                        {t.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {selectedTypeInfo && (
                  <p className="text-xs text-muted-foreground">{selectedTypeInfo.description}</p>
                )}
              </div>

              {/* Amount + Currency */}
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label htmlFor="amount">Amount</Label>
                  <Input
                    id="amount"
                    type="number"
                    min="0.01"
                    step="0.01"
                    placeholder="0.00"
                    value={amountStr}
                    onChange={(e) => setAmountStr(e.target.value)}
                    required
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="currency">Currency</Label>
                  <Select value={currency} onValueChange={setCurrency}>
                    <SelectTrigger id="currency">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {CURRENCIES.map((c) => (
                        <SelectItem key={c} value={c}>
                          {c.toUpperCase()}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {/* Type-specific target fields */}
              {type === "WALLET_TRANSFER" && (
                <div className="space-y-1.5">
                  <Label htmlFor="to_user_sub">Recipient user ID</Label>
                  <Input
                    id="to_user_sub"
                    placeholder="user@example.com or user sub"
                    value={targetFields["to_user_sub"] ?? ""}
                    onChange={(e) => setField("to_user_sub", e.target.value)}
                    required
                  />
                </div>
              )}

              {type === "FREE_FORM" && (
                <div className="space-y-1.5">
                  <Label htmlFor="to_user_sub">Recipient user ID (optional)</Label>
                  <Input
                    id="to_user_sub"
                    placeholder="user@example.com or user sub"
                    value={targetFields["to_user_sub"] ?? ""}
                    onChange={(e) => setField("to_user_sub", e.target.value)}
                  />
                </div>
              )}

              {type === "PAYOUT" && (
                <div className="space-y-1.5">
                  <Label htmlFor="payout_method_id">Payout method ID</Label>
                  <Input
                    id="payout_method_id"
                    placeholder="pm_xxxxxxxxxxxxxxxx"
                    value={targetFields["payout_method_id"] ?? ""}
                    onChange={(e) => setField("payout_method_id", e.target.value)}
                    required
                  />
                </div>
              )}

              {type === "REFUND" && (
                <div className="space-y-1.5">
                  <Label htmlFor="payment_intent_id">Payment intent ID</Label>
                  <Input
                    id="payment_intent_id"
                    placeholder="pi_xxxxxxxxxxxxxxxx"
                    value={targetFields["payment_intent_id"] ?? ""}
                    onChange={(e) => setField("payment_intent_id", e.target.value)}
                    required
                  />
                  <p className="text-xs text-muted-foreground">
                    Must start with <code>pi_</code>
                  </p>
                </div>
              )}

              {type === "COUNTERPARTY" && (
                <div className="space-y-1.5">
                  <Label htmlFor="counterparty_ref">Counterparty reference</Label>
                  <Input
                    id="counterparty_ref"
                    placeholder="IBAN, sort code, or reference"
                    value={targetFields["counterparty_ref"] ?? ""}
                    onChange={(e) => setField("counterparty_ref", e.target.value)}
                    required
                  />
                </div>
              )}

              {/* Reason */}
              <div className="space-y-1.5">
                <Label htmlFor="reason">Reason / note (optional)</Label>
                <Textarea
                  id="reason"
                  placeholder="Optional description for this transfer"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  rows={2}
                />
              </div>

              <Button type="submit" disabled={submitting} className="w-full sm:w-auto">
                {submitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Create Transfer
              </Button>
            </form>
          </CardContent>
        </Card>
      )}

      {/* ── SCA STEP ── */}
      {step === "sca" && txnRequest && txnRequest.sca_challenge_id && (
        <div className="space-y-4">
          <Card>
            <CardContent className="pt-4">
              <TxnRequestSummary txn={txnRequest} />
            </CardContent>
          </Card>
          <ScaChallengePanel
            challengeId={txnRequest.sca_challenge_id}
            requiredFactors={txnRequest.sca_required_factors ?? txnRequest.required_factors ?? ["email"]}
            onComplete={handleScaComplete}
          />
        </div>
      )}

      {/* ── EXECUTE STEP ── */}
      {step === "execute" && txnRequest && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Confirm Transfer</CardTitle>
            <CardDescription>
              Review the details below and click Execute to move funds.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <TxnRequestSummary txn={txnRequest} />
            <Button
              onClick={() => handleExecute(txnRequest.request_id)}
              disabled={executing}
              className="w-full sm:w-auto"
            >
              {executing && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Execute Transfer
            </Button>
          </CardContent>
        </Card>
      )}

      {/* ── DONE ── */}
      {step === "done" && txnRequest && (
        <Card className="border-green-300 bg-green-50 dark:bg-green-950 dark:border-green-800">
          <CardContent className="pt-6 space-y-4">
            <div className="flex items-center gap-2 text-green-700 dark:text-green-300 font-medium">
              <CheckCircle2 className="h-5 w-5" />
              Transfer completed
            </div>
            <TxnRequestSummary txn={txnRequest} />
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => navigate(`/bank/transfers/${txnRequest.request_id}`)}
              >
                View Details
              </Button>
              <Button
                size="sm"
                onClick={() => {
                  setStep("form");
                  setTxnRequest(null);
                  setAmountStr("");
                  setReason("");
                  setTargetFields({});
                }}
              >
                New Transfer
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── ERROR ── */}
      {step === "error" && (
        <Card className="border-red-300 bg-red-50 dark:bg-red-950 dark:border-red-800">
          <CardContent className="pt-6 space-y-4">
            <div className="flex items-start gap-2 text-red-700 dark:text-red-300">
              <AlertCircle className="h-5 w-5 mt-0.5 flex-shrink-0" />
              <div>
                <p className="font-medium">Transfer failed</p>
                {errorMsg && <p className="text-sm mt-1">{errorMsg}</p>}
                {txnRequest?.failure_reason && (
                  <p className="text-sm mt-1 font-mono text-xs">{txnRequest.failure_reason}</p>
                )}
              </div>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setStep("form");
                setErrorMsg("");
              }}
            >
              Try Again
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Mini summary component ───────────────────────────────────────────────────

function TxnRequestSummary({ txn }: { txn: TxnRequestOut }) {
  return (
    <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
      <div>
        <dt className="text-muted-foreground">Amount</dt>
        <dd className="font-semibold">{formatCurrency(txn.amount_cents, txn.currency)}</dd>
      </div>
      <div>
        <dt className="text-muted-foreground">Type</dt>
        <dd>{txn.type.replace(/_/g, " ")}</dd>
      </div>
      <div>
        <dt className="text-muted-foreground">Status</dt>
        <dd>
          <span
            className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${STATUS_BADGE[txn.status as keyof typeof STATUS_BADGE] ?? ""}`}
          >
            {STATUS_LABEL[txn.status as keyof typeof STATUS_LABEL] ?? txn.status}
          </span>
        </dd>
      </div>
      <div>
        <dt className="text-muted-foreground">Request ID</dt>
        <dd className="font-mono text-xs truncate" title={txn.request_id}>
          {txn.request_id}
        </dd>
      </div>
      {txn.failure_reason && (
        <div className="col-span-2">
          <dt className="text-muted-foreground">Failure reason</dt>
          <dd className="text-red-600 dark:text-red-400 text-xs font-mono">
            {txn.failure_reason}
          </dd>
        </div>
      )}
    </dl>
  );
}
