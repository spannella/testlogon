/**
 * ScaChallengePanel — TXR-003/TXR-005
 *
 * Step-up SCA widget displayed when a transaction request lands in PENDING status.
 * Supports email, sms, and totp factors by calling the existing /ui/mfa/* endpoints.
 * After all required factors pass, parent can call onComplete() to proceed to execution.
 */

import { useState } from "react";
import { toast } from "sonner";
import { ShieldCheck, Loader2, Mail, MessageSquare, Smartphone } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

import {
  scaEmailBegin,
  scaEmailVerify,
  scaSmsBegin,
  scaSmsVerify,
  scaTotpVerify,
  type ScaChallengeProgress,
} from "@/api/endpoints/txnRequests";
import { ApiError } from "@/api/client";

interface ScaChallengePanelProps {
  challengeId: string;
  requiredFactors: string[];
  onComplete: () => void;
}

function factorLabel(factor: string): string {
  if (factor === "email") return "Email code";
  if (factor === "sms") return "SMS code";
  if (factor === "totp") return "Authenticator code";
  return factor;
}

function factorIcon(factor: string) {
  if (factor === "email") return <Mail className="h-4 w-4" />;
  if (factor === "sms") return <MessageSquare className="h-4 w-4" />;
  return <Smartphone className="h-4 w-4" />;
}

export function ScaChallengePanel({
  challengeId,
  requiredFactors,
  onComplete,
}: ScaChallengePanelProps) {
  const [currentFactor, setCurrentFactor] = useState<string>(requiredFactors[0] ?? "email");
  const [passed, setPassed] = useState<Record<string, boolean>>({});
  const [remaining, setRemaining] = useState<string[]>(requiredFactors);
  const [code, setCode] = useState("");
  const [sending, setSending] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [codeSent, setCodeSent] = useState(false);

  const allDone = remaining.length === 0;

  function applyProgress(progress: ScaChallengeProgress) {
    setPassed(progress.passed ?? {});
    setRemaining(progress.remaining_factors ?? []);
    if (progress.remaining_factors && progress.remaining_factors.length > 0) {
      setCurrentFactor(progress.remaining_factors[0] ?? "email");
      setCode("");
      setCodeSent(false);
    }
  }

  async function handleSend() {
    setSending(true);
    try {
      if (currentFactor === "email") {
        await scaEmailBegin(challengeId);
        toast.success("Email code sent — check your inbox");
      } else if (currentFactor === "sms") {
        await scaSmsBegin(challengeId);
        toast.success("SMS code sent");
      }
      setCodeSent(true);
    } catch (err) {
      const msg = err instanceof ApiError ? err.detail : "Failed to send code";
      toast.error(msg);
    } finally {
      setSending(false);
    }
  }

  async function handleVerify() {
    if (!code.trim()) {
      toast.error("Enter the verification code");
      return;
    }
    setVerifying(true);
    try {
      let progress: ScaChallengeProgress;
      if (currentFactor === "totp") {
        progress = await scaTotpVerify(challengeId, code.trim());
      } else if (currentFactor === "sms") {
        progress = await scaSmsVerify(challengeId, code.trim());
      } else {
        progress = await scaEmailVerify(challengeId, code.trim());
      }
      toast.success(`${factorLabel(currentFactor)} verified`);
      applyProgress(progress);
      if (progress.remaining_factors && progress.remaining_factors.length === 0) {
        onComplete();
      }
    } catch (err) {
      const msg = err instanceof ApiError ? err.detail : "Verification failed";
      toast.error(msg);
    } finally {
      setVerifying(false);
    }
  }

  if (allDone) {
    return (
      <div className="flex items-center gap-2 text-green-600 font-medium py-2">
        <ShieldCheck className="h-5 w-5" />
        <span>SCA authorised — proceeding…</span>
      </div>
    );
  }

  return (
    <Card className="border-yellow-300 bg-yellow-50 dark:bg-yellow-950 dark:border-yellow-800">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldCheck className="h-5 w-5 text-yellow-600" />
          Strong Customer Authentication required
        </CardTitle>
        <CardDescription className="text-yellow-700 dark:text-yellow-300">
          This transfer requires additional identity verification before funds move.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Factor progress pills */}
        <div className="flex flex-wrap gap-2">
          {requiredFactors.map((f) => (
            <span
              key={f}
              className={`inline-flex items-center gap-1 rounded-full px-3 py-0.5 text-xs font-medium ${
                passed[f]
                  ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                  : f === currentFactor
                  ? "bg-yellow-200 text-yellow-900 dark:bg-yellow-800 dark:text-yellow-100"
                  : "bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400"
              }`}
            >
              {factorIcon(f)}
              {factorLabel(f)}
              {passed[f] && " ✓"}
            </span>
          ))}
        </div>

        {/* Current factor form */}
        <div className="space-y-3">
          <Label className="text-sm font-medium capitalize">
            {factorLabel(currentFactor)}
          </Label>

          {/* Send button for OTP factors */}
          {(currentFactor === "email" || currentFactor === "sms") && !codeSent && (
            <Button
              variant="outline"
              size="sm"
              onClick={handleSend}
              disabled={sending}
              className="w-full sm:w-auto"
            >
              {sending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Send {factorLabel(currentFactor)}
            </Button>
          )}

          {(currentFactor === "totp" || codeSent) && (
            <div className="flex gap-2">
              <Input
                type="text"
                inputMode="numeric"
                placeholder={
                  currentFactor === "totp"
                    ? "6-digit authenticator code"
                    : "Verification code from message"
                }
                value={code}
                onChange={(e) => setCode(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleVerify()}
                maxLength={8}
                className="max-w-[200px]"
              />
              <Button onClick={handleVerify} disabled={verifying || !code.trim()} size="sm">
                {verifying && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Verify
              </Button>
              {(currentFactor === "email" || currentFactor === "sms") && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setCodeSent(false);
                    setCode("");
                    handleSend();
                  }}
                  disabled={sending}
                >
                  Resend
                </Button>
              )}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
