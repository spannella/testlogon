/**
 * TransferDetailPage — TXR-002 + TXR-004 + TXR-005
 *
 * Shows a single transaction request with its current status.
 * If status is PENDING (SCA required), renders ScaChallengePanel.
 * If status is INITIATED or SCA-complete, offers Execute button.
 *
 * Route: /bank/transfers/:requestId
 */

import { useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ChevronLeft,
  Loader2,
  RefreshCw,
  AlertCircle,
  CheckCircle2,
  Clock,
  XCircle,
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
import { Badge } from "@/components/ui/badge";

import {
  getTxnRequest,
  executeTxnRequest,
} from "@/api/endpoints/txnRequests";
import { ApiError } from "@/api/client";

import { ScaChallengePanel } from "./ScaChallengePanel";
import {
  formatCurrency,
  fmtTs,
  STATUS_BADGE,
  STATUS_LABEL,
  TYPE_LABEL,
  needsSca,
  canExecute,
} from "./txrUtils";

// ─── Status icon helper ───────────────────────────────────────────────────────

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case "COMPLETED":
      return <CheckCircle2 className="h-5 w-5 text-green-500" />;
    case "FAILED":
      return <XCircle className="h-5 w-5 text-red-500" />;
    case "IN_FLIGHT":
      return <Loader2 className="h-5 w-5 animate-spin text-purple-500" />;
    case "PENDING":
      return <AlertCircle className="h-5 w-5 text-yellow-500" />;
    default:
      return <Clock className="h-5 w-5 text-blue-500" />;
  }
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function TransferDetailPage() {
  const { requestId } = useParams<{ requestId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [executing, setExecuting] = useState(false);
  const [scaComplete, setScaComplete] = useState(false);

  const { data: txn, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["txnRequests", requestId],
    queryFn: () => getTxnRequest(requestId!),
    enabled: !!requestId,
    refetchInterval: (query) => {
      // Poll while IN_FLIGHT
      const status = query.state.data?.status;
      return status === "IN_FLIGHT" ? 3000 : false;
    },
    retry: (count, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) return false;
      return count < 2;
    },
  });

  // ── Execute ───────────────────────────────────────────────────────────────

  async function handleExecute() {
    if (!txn) return;
    setExecuting(true);
    try {
      const updated = await executeTxnRequest(txn.request_id);
      queryClient.setQueryData(["txnRequests", requestId], updated);
      queryClient.invalidateQueries({ queryKey: ["txnRequests"] });
      if (updated.status === "COMPLETED") {
        toast.success("Transfer completed successfully");
      }
    } catch (err) {
      const msg = err instanceof ApiError ? err.detail : "Execution failed";
      toast.error(msg);
      refetch();
    } finally {
      setExecuting(false);
    }
  }

  // ── SCA complete → execute ─────────────────────────────────────────────────

  async function handleScaComplete() {
    setScaComplete(true);
    await handleExecute();
  }

  // ── Loading ──────────────────────────────────────────────────────────────

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 p-6 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin" />
        Loading transfer…
      </div>
    );
  }

  // ── Feature disabled ───────────────────────────────────────────────────────

  if (isError) {
    const apiErr = error instanceof ApiError ? error : null;
    const disabled = apiErr && (apiErr.status === 404 || apiErr.status === 503);
    return (
      <div className="p-6 space-y-4 max-w-lg">
        <PageHeader
          title="Transfer"
          actions={
            <Button variant="ghost" size="sm" onClick={() => navigate("/bank/transfers")}>
              <ChevronLeft className="mr-1 h-4 w-4" />
              Back
            </Button>
          }
        />
        <Card className="border-red-200 bg-red-50 dark:bg-red-950 dark:border-red-800">
          <CardContent className="pt-6 flex items-start gap-2">
            <AlertCircle className="h-5 w-5 text-red-500 mt-0.5 flex-shrink-0" />
            <div>
              <p className="font-medium text-red-700 dark:text-red-300">
                {disabled
                  ? "Transaction requests are not enabled on this platform."
                  : "Could not load transfer"}
              </p>
              {!disabled && apiErr && (
                <p className="text-sm text-red-600 dark:text-red-400 mt-1">{apiErr.detail}</p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!txn) return null;

  const isExecutable = canExecute(txn.status) && !needsSca(txn.status);
  const showSca =
    needsSca(txn.status) && txn.sca_challenge_id && !scaComplete;

  return (
    <div className="space-y-6 p-4 sm:p-6 max-w-2xl">
      <PageHeader
        title="Transfer Details"
        description={`Request ID: ${txn.request_id}`}
        actions={
          <div className="flex gap-2">
            <Button variant="ghost" size="sm" onClick={() => refetch()}>
              <RefreshCw className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="sm" onClick={() => navigate("/bank/transfers")}>
              <ChevronLeft className="mr-1 h-4 w-4" />
              Back
            </Button>
          </div>
        }
      />

      {/* ── Status card ── */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center gap-3">
            <StatusIcon status={txn.status} />
            <div>
              <CardTitle className="text-base">
                {formatCurrency(txn.amount_cents, txn.currency)}
              </CardTitle>
              <CardDescription>
                {TYPE_LABEL[txn.type as keyof typeof TYPE_LABEL] ?? txn.type}
              </CardDescription>
            </div>
            <Badge
              className={`ml-auto ${STATUS_BADGE[txn.status as keyof typeof STATUS_BADGE] ?? ""}`}
              variant="outline"
            >
              {STATUS_LABEL[txn.status as keyof typeof STATUS_LABEL] ?? txn.status}
            </Badge>
          </div>
        </CardHeader>

        <CardContent>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm">
            <div>
              <dt className="text-muted-foreground">Amount</dt>
              <dd className="font-semibold">{formatCurrency(txn.amount_cents, txn.currency)}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Currency</dt>
              <dd>{txn.currency.toUpperCase()}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Type</dt>
              <dd>{TYPE_LABEL[txn.type as keyof typeof TYPE_LABEL] ?? txn.type}</dd>
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
              <dt className="text-muted-foreground">Created</dt>
              <dd>{fmtTs(txn.created_at)}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground">Updated</dt>
              <dd>{fmtTs(txn.updated_at)}</dd>
            </div>

            {/* Target fields */}
            {Object.entries(txn.target).map(([k, v]) => (
              <div key={k} className="col-span-2 sm:col-span-1">
                <dt className="text-muted-foreground capitalize">{k.replace(/_/g, " ")}</dt>
                <dd className="font-mono text-xs break-all">{String(v)}</dd>
              </div>
            ))}

            {txn.failure_reason && (
              <div className="col-span-2">
                <dt className="text-muted-foreground">Failure reason</dt>
                <dd className="text-red-600 dark:text-red-400 font-mono text-xs">
                  {txn.failure_reason}
                </dd>
              </div>
            )}

            {txn.ledger_refs && txn.ledger_refs.length > 0 && (
              <div className="col-span-2">
                <dt className="text-muted-foreground">Ledger refs</dt>
                <dd className="font-mono text-xs space-y-0.5">
                  {txn.ledger_refs.map((ref) => (
                    <div key={ref}>{ref}</div>
                  ))}
                </dd>
              </div>
            )}

            {txn.sca_challenge_id && (
              <div className="col-span-2">
                <dt className="text-muted-foreground">SCA challenge</dt>
                <dd className="font-mono text-xs">{txn.sca_challenge_id}</dd>
              </div>
            )}
          </dl>

          {/* Execute button (no SCA required) */}
          {isExecutable && (
            <div className="mt-4 pt-4 border-t">
              <Button onClick={handleExecute} disabled={executing}>
                {executing && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Execute Transfer
              </Button>
              <p className="text-xs text-muted-foreground mt-2">
                This will move funds immediately. The action cannot be undone.
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* ── SCA panel ── */}
      {showSca && (
        <ScaChallengePanel
          challengeId={txn.sca_challenge_id!}
          requiredFactors={
            txn.sca_required_factors ?? txn.required_factors ?? ["email"]
          }
          onComplete={handleScaComplete}
        />
      )}

      {/* ── Completed ledger summary ── */}
      {txn.status === "COMPLETED" && (
        <Card className="border-green-200 bg-green-50 dark:bg-green-950 dark:border-green-800">
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 text-green-700 dark:text-green-300">
              <CheckCircle2 className="h-5 w-5" />
              <span className="font-medium">
                Transfer of {formatCurrency(txn.amount_cents, txn.currency)} completed
              </span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Back link */}
      <Link
        to="/bank/transfers"
        className="text-sm text-muted-foreground hover:text-foreground flex items-center gap-1"
      >
        <ChevronLeft className="h-3.5 w-3.5" />
        All transfers
      </Link>
    </div>
  );
}
