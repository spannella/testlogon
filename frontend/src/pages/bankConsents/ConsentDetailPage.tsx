/**
 * ConsentDetailPage — CSN-001 / CSN-002 / CSN-004 / CSN-006
 *
 * Shows a single PSD2 consent with scopes, accounts, status, and SCA flow.
 * Handles feature flag off (404/503) gracefully.
 *
 * Route: /bank/consents/:consentId
 */

import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ShieldCheck,
  ArrowLeft,
  AlertCircle,
  Loader2,
  RefreshCw,
  XCircle,
  CheckCircle2,
  Clock,
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
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { ApiError } from "@/api/client";
import {
  getConsent,
  revokeConsent,
  beginConsentSca,
  acceptConsent,
  type ConsentOut,
  type ConsentStatus,
} from "@/api/endpoints/psd2Consents";
import {
  STATUS_BADGE,
  STATUS_LABEL,
  typeLabel,
  canRevoke,
  needsAcceptance,
  fmtTs,
  fmtDate,
} from "./consentUtils";

// ─── Feature-disabled / not-found states ─────────────────────────────────────

function StatusMessage({ icon, title, message }: { icon: React.ReactNode; title: string; message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 gap-4 text-center">
      {icon}
      <div>
        <p className="font-semibold text-lg">{title}</p>
        <p className="text-sm text-muted-foreground mt-1">{message}</p>
      </div>
      <Button asChild variant="outline" size="sm">
        <Link to="/bank/consents">Back to consents</Link>
      </Button>
    </div>
  );
}

// ─── Consent detail card ──────────────────────────────────────────────────────

function ConsentFields({ consent }: { consent: ConsentOut }) {
  const now = Math.floor(Date.now() / 1000);
  const isExpiredByTime = consent.valid_until < now;

  return (
    <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-4 text-sm">
      <div>
        <dt className="text-muted-foreground font-medium">Consent ID</dt>
        <dd className="font-mono text-xs mt-0.5 break-all">{consent.consent_id}</dd>
      </div>
      <div>
        <dt className="text-muted-foreground font-medium">Consumer</dt>
        <dd className="mt-0.5">{consent.consumer_ref}</dd>
      </div>
      <div>
        <dt className="text-muted-foreground font-medium">Type</dt>
        <dd className="mt-0.5">{typeLabel(consent.consent_type)}</dd>
      </div>
      <div>
        <dt className="text-muted-foreground font-medium">Recurring</dt>
        <dd className="mt-0.5">{consent.recurring ? "Yes" : "No"}</dd>
      </div>
      <div>
        <dt className="text-muted-foreground font-medium">Accounts covered</dt>
        <dd className="mt-0.5">
          {consent.account_refs.length > 0 ? (
            <ul className="list-disc list-inside space-y-0.5">
              {consent.account_refs.map((ref) => (
                <li key={ref} className="font-mono text-xs">{ref}</li>
              ))}
            </ul>
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </dd>
      </div>
      <div>
        <dt className="text-muted-foreground font-medium">View permissions</dt>
        <dd className="mt-0.5 flex flex-wrap gap-1">
          {(consent.view_refs ?? []).map((vr) => (
            <Badge key={vr} variant="secondary" className="text-xs capitalize">
              {vr}
            </Badge>
          ))}
        </dd>
      </div>
      {consent.payment_ref && (
        <div>
          <dt className="text-muted-foreground font-medium">Payment reference</dt>
          <dd className="mt-0.5 font-mono text-xs">{consent.payment_ref}</dd>
        </div>
      )}
      {consent.reason && (
        <div className="sm:col-span-2">
          <dt className="text-muted-foreground font-medium">Reason</dt>
          <dd className="mt-0.5">{consent.reason}</dd>
        </div>
      )}
      <div>
        <dt className="text-muted-foreground font-medium">Valid from</dt>
        <dd className="mt-0.5">{fmtTs(consent.valid_from)}</dd>
      </div>
      <div>
        <dt className="text-muted-foreground font-medium">Valid until</dt>
        <dd className={`mt-0.5 ${isExpiredByTime && consent.status === "ACCEPTED" ? "text-destructive" : ""}`}>
          {fmtDate(consent.valid_until)}
          {isExpiredByTime && consent.status !== "REVOKED" && consent.status !== "EXPIRED" && (
            <span className="ml-1 text-xs text-destructive">(expired)</span>
          )}
        </dd>
      </div>
      <div>
        <dt className="text-muted-foreground font-medium">Created</dt>
        <dd className="mt-0.5">{fmtTs(consent.created_at)}</dd>
      </div>
      <div>
        <dt className="text-muted-foreground font-medium">Last updated</dt>
        <dd className="mt-0.5">{fmtTs(consent.updated_at)}</dd>
      </div>
      {consent.revoked_at && (
        <div>
          <dt className="text-muted-foreground font-medium">Revoked at</dt>
          <dd className="mt-0.5 text-destructive">{fmtTs(consent.revoked_at)}</dd>
        </div>
      )}
      {consent.sca_challenge_id && (
        <div>
          <dt className="text-muted-foreground font-medium">SCA challenge</dt>
          <dd className="mt-0.5 font-mono text-xs">{consent.sca_challenge_id}</dd>
        </div>
      )}
    </dl>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function ConsentDetailPage() {
  const { consentId } = useParams<{ consentId: string }>();
  const qc = useQueryClient();

  const [revokeOpen, setRevokeOpen] = useState(false);
  const [scaStep, setScaStep] = useState<"idle" | "sca_pending" | "accepting">("idle");
  const [challengeId, setChallengeId] = useState<string | null>(null);
  const [requiredFactors, setRequiredFactors] = useState<string[]>([]);

  const query = useQuery({
    queryKey: ["psd2-consents", "detail", consentId],
    queryFn: () => getConsent(consentId!),
    enabled: !!consentId,
    retry: (failureCount, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) {
        return false;
      }
      return failureCount < 2;
    },
  });

  const revokeMut = useMutation({
    mutationFn: () => revokeConsent(consentId!),
    onSuccess: () => {
      toast.success("Consent revoked");
      setRevokeOpen(false);
      void qc.invalidateQueries({ queryKey: ["psd2-consents"] });
    },
    onError: (err: unknown) => {
      const msg = err instanceof ApiError ? err.detail : "Failed to revoke consent";
      toast.error(msg);
      setRevokeOpen(false);
    },
  });

  const scaMut = useMutation({
    mutationFn: () => beginConsentSca(consentId!),
    onSuccess: (data) => {
      setChallengeId(data.challenge_id);
      setRequiredFactors(data.required_factors ?? []);
      setScaStep("sca_pending");
      toast.info("SCA challenge started — complete your verification factors.");
    },
    onError: (err: unknown) => {
      const msg = err instanceof ApiError ? err.detail : "Failed to start SCA";
      toast.error(msg);
    },
  });

  const acceptMut = useMutation({
    mutationFn: () => acceptConsent(consentId!),
    onSuccess: () => {
      toast.success("Consent accepted");
      setScaStep("idle");
      void qc.invalidateQueries({ queryKey: ["psd2-consents"] });
    },
    onError: (err: unknown) => {
      const msg = err instanceof ApiError ? err.detail : "Failed to accept consent";
      toast.error(msg);
    },
  });

  const consent = query.data;

  const isDisabled =
    query.isError &&
    query.error instanceof ApiError &&
    (query.error.status === 404 || query.error.status === 503);

  const isNotFound =
    query.isError &&
    query.error instanceof ApiError &&
    query.error.status === 404 &&
    !isDisabled;

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <div className="flex items-center gap-2">
        <Button asChild variant="ghost" size="sm">
          <Link to="/bank/consents">
            <ArrowLeft className="h-4 w-4 mr-1" />
            Consents
          </Link>
        </Button>
      </div>

      <PageHeader
        title="Consent detail"
        description={consent ? `${consent.consumer_ref} — ${typeLabel(consent.consent_type)}` : "Loading…"}
      />

      {isDisabled && (
        <StatusMessage
          icon={<AlertCircle className="h-12 w-12 text-muted-foreground" />}
          title="PSD2 Consents not enabled"
          message="This feature requires OPEN_BANK_PROJECT_ENABLED and PSD2_CONSENTS_ENABLED to be active."
        />
      )}

      {isNotFound && (
        <StatusMessage
          icon={<XCircle className="h-12 w-12 text-muted-foreground" />}
          title="Consent not found"
          message="This consent does not exist or does not belong to your account."
        />
      )}

      {query.isLoading && (
        <Card>
          <CardHeader>
            <Skeleton className="h-6 w-48" />
          </CardHeader>
          <CardContent className="space-y-3">
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-4 w-1/2" />
          </CardContent>
        </Card>
      )}

      {consent && (
        <>
          {/* Status banner */}
          <div className="flex items-center gap-3 flex-wrap">
            <Badge
              className={`text-sm px-3 py-1 ${STATUS_BADGE[consent.status as ConsentStatus] ?? ""}`}
            >
              {STATUS_LABEL[consent.status as ConsentStatus] ?? consent.status}
            </Badge>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => void query.refetch()}
              disabled={query.isFetching}
              data-testid="refresh-btn"
            >
              {query.isFetching ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="h-4 w-4" />
              )}
            </Button>
          </div>

          {/* Detail card */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <ShieldCheck className="h-5 w-5" />
                Consent details
              </CardTitle>
              <CardDescription>
                {consentId}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ConsentFields consent={consent} />
            </CardContent>
          </Card>

          {/* SCA / Accept flow */}
          {needsAcceptance(consent.status as ConsentStatus) && (
            <Card className="border-blue-300 bg-blue-50 dark:bg-blue-950 dark:border-blue-800">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Clock className="h-5 w-5 text-blue-600" />
                  Acceptance required
                </CardTitle>
                <CardDescription className="text-blue-700 dark:text-blue-300">
                  This consent is in INITIATED status. Complete SCA to activate it.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {scaStep === "idle" && (
                  <Button
                    onClick={() => scaMut.mutate()}
                    disabled={scaMut.isPending}
                    variant="outline"
                    data-testid="begin-sca-btn"
                  >
                    {scaMut.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    Begin SCA verification
                  </Button>
                )}

                {scaStep === "sca_pending" && (
                  <div className="space-y-3">
                    <p className="text-sm text-muted-foreground">
                      Challenge ID:{" "}
                      <span className="font-mono text-xs">{challengeId}</span>
                    </p>
                    {requiredFactors.length > 0 && (
                      <p className="text-sm text-muted-foreground">
                        Required factors: {requiredFactors.join(", ")}
                      </p>
                    )}
                    <p className="text-sm">
                      Complete verification through your MFA app or enrolled channels, then click Accept.
                    </p>
                    <Button
                      onClick={() => acceptMut.mutate()}
                      disabled={acceptMut.isPending}
                      data-testid="accept-consent-btn"
                    >
                      {acceptMut.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                      <CheckCircle2 className="h-4 w-4 mr-1" />
                      Accept consent
                    </Button>
                  </div>
                )}

                {/* Fallback: no SCA required */}
                {scaStep === "idle" && !consent.sca_challenge_id && (
                  <Button
                    variant="secondary"
                    onClick={() => acceptMut.mutate()}
                    disabled={acceptMut.isPending}
                    data-testid="accept-direct-btn"
                  >
                    {acceptMut.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    Accept without SCA
                  </Button>
                )}
              </CardContent>
            </Card>
          )}

          {/* Revoke action */}
          {canRevoke(consent.status as ConsentStatus) && (
            <div className="flex justify-end">
              <Button
                variant="destructive"
                size="sm"
                onClick={() => setRevokeOpen(true)}
                data-testid="revoke-btn"
              >
                <XCircle className="h-4 w-4 mr-1" />
                Revoke consent
              </Button>
            </div>
          )}

          {/* Accepted notice */}
          {consent.status === "ACCEPTED" && (
            <Card className="border-green-300 bg-green-50 dark:bg-green-950 dark:border-green-800">
              <CardContent className="flex items-center gap-3 py-4">
                <CheckCircle2 className="h-6 w-6 text-green-600 shrink-0" />
                <div>
                  <p className="font-medium text-green-900 dark:text-green-100">
                    Consent is active
                  </p>
                  <p className="text-sm text-green-700 dark:text-green-300">
                    {consent.consumer_ref} has access until {fmtDate(consent.valid_until)}.
                  </p>
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* Revoke confirmation dialog */}
      <Dialog open={revokeOpen} onOpenChange={setRevokeOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Revoke consent</DialogTitle>
            <DialogDescription>
              This will immediately revoke access for{" "}
              <strong>{consent?.consumer_ref ?? "this third party"}</strong>. This action cannot be
              undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => setRevokeOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => revokeMut.mutate()}
              disabled={revokeMut.isPending}
              data-testid="confirm-revoke-btn"
            >
              {revokeMut.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Revoke
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
