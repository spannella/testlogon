/**
 * CreateConsentPage — CSN-001 / CSN-003
 *
 * Form to create a new AIS or PIS consent in INITIATED status.
 * Handles feature flag off (404/503) gracefully.
 *
 * Route: /bank/consents/new
 */

import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowLeft, Plus, AlertCircle, Loader2 } from "lucide-react";

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
import { ApiError } from "@/api/client";
import {
  createConsent,
  type ConsentType,
} from "@/api/endpoints/psd2Consents";

// ─── Valid view refs ──────────────────────────────────────────────────────────

const VIEW_REF_OPTIONS = ["owner", "accountant", "auditor", "public"];

// ─── Feature-disabled state ───────────────────────────────────────────────────

function FeatureDisabled() {
  return (
    <div className="flex flex-col items-center justify-center py-20 gap-4 text-center">
      <AlertCircle className="h-12 w-12 text-muted-foreground" />
      <div>
        <p className="font-semibold text-lg">PSD2 Consents not enabled</p>
        <p className="text-sm text-muted-foreground mt-1">
          This feature requires OPEN_BANK_PROJECT_ENABLED and PSD2_CONSENTS_ENABLED.
        </p>
      </div>
      <Button asChild variant="outline" size="sm">
        <Link to="/bank/consents">Back to consents</Link>
      </Button>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function CreateConsentPage() {
  const navigate = useNavigate();

  const [consumerRef, setConsumerRef] = useState("");
  const [consentType, setConsentType] = useState<ConsentType>("AIS");
  const [accountRefsRaw, setAccountRefsRaw] = useState("");
  const [selectedViewRefs, setSelectedViewRefs] = useState<string[]>(["owner"]);
  const [paymentRef, setPaymentRef] = useState("");
  const [validUntilDate, setValidUntilDate] = useState("");
  const [recurring, setRecurring] = useState(true);
  const [reason, setReason] = useState("");

  const [disabled, setDisabled] = useState(false);

  const mut = useMutation({
    mutationFn: () => {
      const accountRefs = accountRefsRaw
        .split(/[,\n]/)
        .map((s) => s.trim())
        .filter(Boolean);

      const validUntil = validUntilDate
        ? Math.floor(new Date(validUntilDate).getTime() / 1000)
        : undefined;

      return createConsent({
        consumer_ref: consumerRef.trim(),
        consent_type: consentType,
        account_refs: accountRefs,
        view_refs: selectedViewRefs,
        payment_ref: consentType === "PIS" && paymentRef.trim() ? paymentRef.trim() : undefined,
        valid_until: validUntil,
        recurring,
        reason: reason.trim() || undefined,
      });
    },
    onSuccess: (data) => {
      toast.success("Consent created");
      navigate(`/bank/consents/${data.consent_id}`);
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503)) {
        setDisabled(true);
        return;
      }
      const msg = err instanceof ApiError ? err.detail : "Failed to create consent";
      toast.error(msg);
    },
  });

  if (disabled) {
    return (
      <div className="p-4 md:p-6 lg:p-8">
        <FeatureDisabled />
      </div>
    );
  }

  function toggleViewRef(vr: string) {
    setSelectedViewRefs((prev) =>
      prev.includes(vr) ? prev.filter((x) => x !== vr) : [...prev, vr],
    );
  }

  const isValid =
    consumerRef.trim().length > 0 &&
    accountRefsRaw.trim().length > 0 &&
    selectedViewRefs.length > 0 &&
    (consentType !== "PIS" || paymentRef.trim().length > 0);

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
        title="New consent"
        description="Grant a third party access to your account information or initiate a payment."
      />

      <Card className="max-w-2xl">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Plus className="h-5 w-5" />
            Create consent
          </CardTitle>
          <CardDescription>
            Fill in the consent details. The consent will be created in INITIATED status and must be
            accepted (with SCA if required) before becoming active.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          {/* Consumer reference */}
          <div className="space-y-2">
            <Label htmlFor="consumer-ref">
              Consumer reference <span className="text-destructive">*</span>
            </Label>
            <Input
              id="consumer-ref"
              value={consumerRef}
              onChange={(e) => setConsumerRef(e.target.value)}
              placeholder="tpp-app-12345"
              maxLength={256}
              data-testid="consumer-ref-input"
            />
            <p className="text-xs text-muted-foreground">
              Identifier for the third-party provider (TPP) requesting access.
            </p>
          </div>

          {/* Consent type */}
          <div className="space-y-2">
            <Label htmlFor="consent-type">
              Consent type <span className="text-destructive">*</span>
            </Label>
            <Select
              value={consentType}
              onValueChange={(v) => setConsentType(v as ConsentType)}
            >
              <SelectTrigger id="consent-type" data-testid="consent-type-select">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="AIS">AIS — Account Information Service</SelectItem>
                <SelectItem value="PIS">PIS — Payment Initiation Service</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Account references */}
          <div className="space-y-2">
            <Label htmlFor="account-refs">
              Account references <span className="text-destructive">*</span>
            </Label>
            <Textarea
              id="account-refs"
              value={accountRefsRaw}
              onChange={(e) => setAccountRefsRaw(e.target.value)}
              placeholder="acc-001, acc-002"
              rows={2}
              data-testid="account-refs-input"
            />
            <p className="text-xs text-muted-foreground">
              Comma or newline-separated list of account identifiers.
            </p>
          </div>

          {/* View refs */}
          <div className="space-y-2">
            <Label>
              View permissions <span className="text-destructive">*</span>
            </Label>
            <div className="flex flex-wrap gap-2">
              {VIEW_REF_OPTIONS.map((vr) => (
                <button
                  key={vr}
                  type="button"
                  onClick={() => toggleViewRef(vr)}
                  className={`rounded-full px-3 py-1 text-xs font-medium border transition-colors ${
                    selectedViewRefs.includes(vr)
                      ? "bg-primary text-primary-foreground border-primary"
                      : "bg-background text-foreground border-border hover:bg-muted"
                  }`}
                  data-testid={`view-ref-${vr}`}
                >
                  {vr}
                </button>
              ))}
            </div>
          </div>

          {/* PIS: payment reference */}
          {consentType === "PIS" && (
            <div className="space-y-2">
              <Label htmlFor="payment-ref">
                Payment reference <span className="text-destructive">*</span>
              </Label>
              <Input
                id="payment-ref"
                value={paymentRef}
                onChange={(e) => setPaymentRef(e.target.value)}
                placeholder="pay-xyz-001"
                data-testid="payment-ref-input"
              />
              <p className="text-xs text-muted-foreground">
                Required for PIS consents — identifies the payment to be authorised.
              </p>
            </div>
          )}

          {/* Valid until */}
          <div className="space-y-2">
            <Label htmlFor="valid-until">Valid until (optional)</Label>
            <Input
              id="valid-until"
              type="date"
              value={validUntilDate}
              onChange={(e) => setValidUntilDate(e.target.value)}
              data-testid="valid-until-input"
            />
            <p className="text-xs text-muted-foreground">
              Leave blank to use the server default TTL.
            </p>
          </div>

          {/* Recurring */}
          <div className="flex items-center gap-3">
            <input
              id="recurring"
              type="checkbox"
              checked={recurring}
              onChange={(e) => setRecurring(e.target.checked)}
              className="h-4 w-4 rounded border-border"
              data-testid="recurring-checkbox"
            />
            <Label htmlFor="recurring" className="cursor-pointer">
              Recurring access
            </Label>
          </div>

          {/* Reason */}
          <div className="space-y-2">
            <Label htmlFor="reason">Reason (optional)</Label>
            <Textarea
              id="reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Describe why this access is needed…"
              rows={2}
              maxLength={512}
              data-testid="reason-input"
            />
          </div>

          {/* Submit */}
          <div className="flex gap-3 pt-2">
            <Button
              onClick={() => mut.mutate()}
              disabled={!isValid || mut.isPending}
              data-testid="create-consent-submit"
            >
              {mut.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Create consent
            </Button>
            <Button asChild variant="outline">
              <Link to="/bank/consents">Cancel</Link>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
