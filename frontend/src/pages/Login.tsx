import * as React from "react";
import { useNavigate, Link } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Loader2, Shield, Smartphone, Mail, KeyRound, ArrowLeft } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { OtpInput } from "@/components/ui/otp-input";

import { useAuthStore } from "@/stores/authStore";
import { ApiError } from "@/api/client";
import {
  sessionStart,
  sessionFinalize,
  verifyTotp,
  beginSms,
  verifySms,
  beginEmail,
  verifyEmail,
  useRecoveryCode,
} from "@/api/endpoints/auth";

// ─── Types ───────────────────────────────────────────────────────

type LoginStep = "credentials" | "mfa";
type MfaMethod = "totp" | "sms" | "email" | "recovery";

const credentialsSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(1, "Password is required"),
});

type CredentialsForm = z.infer<typeof credentialsSchema>;

// ─── MFA method config ──────────────────────────────────────────

const MFA_METHODS: Record<MfaMethod, { label: string; icon: React.ReactNode; description: string }> = {
  totp: {
    label: "Authenticator App",
    icon: <Shield className="h-4 w-4" />,
    description: "Enter the 6-digit code from your authenticator app",
  },
  sms: {
    label: "SMS Code",
    icon: <Smartphone className="h-4 w-4" />,
    description: "We'll send a verification code to your phone",
  },
  email: {
    label: "Email Code",
    icon: <Mail className="h-4 w-4" />,
    description: "We'll send a verification code to your email",
  },
  recovery: {
    label: "Recovery Code",
    icon: <KeyRound className="h-4 w-4" />,
    description: "Enter one of your backup recovery codes",
  },
};

// ─── Login Page ─────────────────────────────────────────────────

export default function Login() {
  const navigate = useNavigate();
  const { login, isAuthenticated } = useAuthStore();

  // Redirect if already authenticated
  React.useEffect(() => {
    if (isAuthenticated) {
      navigate("/", { replace: true });
    }
  }, [isAuthenticated, navigate]);

  // Login flow state
  const [step, setStep] = React.useState<LoginStep>("credentials");
  const [challengeId, setChallengeId] = React.useState<string | null>(null);
  const [requiredFactors, setRequiredFactors] = React.useState<string[]>([]);
  const [passedFactors, setPassedFactors] = React.useState<Record<string, boolean>>({});
  const [activeMfa, setActiveMfa] = React.useState<MfaMethod>("totp");
  const [rememberDevice, setRememberDevice] = React.useState(false);

  // MFA input state
  const [otpValue, setOtpValue] = React.useState("");
  const [recoveryCode, setRecoveryCode] = React.useState("");
  const [smsSent, setSmsSent] = React.useState(false);
  const [emailSent, setEmailSent] = React.useState(false);

  // Loading / error
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  // Credentials form
  const form = useForm<CredentialsForm>({
    resolver: zodResolver(credentialsSchema),
    defaultValues: { username: "", password: "" },
  });

  // ── Credentials submit ──────────────────────────────────────────

  const handleCredentials = async (data: CredentialsForm) => {
    setLoading(true);
    setError(null);
    try {
      const resp = await sessionStart({
        challenge_context: {
          username: data.username,
          password: data.password,
        },
      });

      if (!resp.auth_required && resp.session_id) {
        // No MFA required — login complete
        login(resp.session_id, "");
        navigate("/", { replace: true });
        return;
      }

      // MFA required
      setChallengeId(resp.challenge_id ?? null);
      setRequiredFactors(resp.required_factors);

      // Pick the best default MFA method
      const factors = resp.required_factors;
      if (factors.includes("totp")) setActiveMfa("totp");
      else if (factors.includes("sms")) setActiveMfa("sms");
      else if (factors.includes("email")) setActiveMfa("email");
      else setActiveMfa("recovery");

      setStep("mfa");
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.detail || "Invalid credentials. Please try again.");
      } else {
        setError("An unexpected error occurred. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  // ── MFA verify ──────────────────────────────────────────────────

  const handleMfaVerify = async (code?: string) => {
    if (!challengeId) return;
    setLoading(true);
    setError(null);

    try {
      let resp;

      switch (activeMfa) {
        case "totp":
          resp = await verifyTotp({ challenge_id: challengeId, totp_code: code ?? otpValue });
          break;
        case "sms":
          resp = await verifySms({ challenge_id: challengeId, code: code ?? otpValue });
          break;
        case "email":
          resp = await verifyEmail({ challenge_id: challengeId, code: code ?? otpValue });
          break;
        case "recovery":
          resp = await useRecoveryCode(activeMfa, {
            challenge_id: challengeId,
            recovery_code: recoveryCode,
          });
          break;
      }

      if (!resp) return;

      setPassedFactors(resp.passed);

      // Check if all factors are satisfied
      if (resp.remaining_factors.length === 0) {
        // Finalize the session
        const finalResp = await sessionFinalize({
          challenge_id: challengeId,
          remember_device: rememberDevice,
        });

        if (finalResp.status === "ok" && finalResp.session_id) {
          login(finalResp.session_id, "");
          navigate("/", { replace: true });
        } else if (finalResp.required_factors.length > 0) {
          // More factors needed
          setRequiredFactors(finalResp.required_factors);
          setPassedFactors(finalResp.passed);
          setOtpValue("");
          setRecoveryCode("");
        }
      } else {
        // More factors needed
        setRequiredFactors(resp.required_factors);
        setOtpValue("");
        setRecoveryCode("");
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.detail || "Verification failed. Please try again.");
      } else {
        setError("An unexpected error occurred. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  // ── Send SMS/Email code ─────────────────────────────────────────

  const handleSendSms = async () => {
    if (!challengeId) return;
    setLoading(true);
    setError(null);
    try {
      await beginSms({ challenge_id: challengeId });
      setSmsSent(true);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.detail || "Failed to send SMS code.");
      } else {
        setError("Failed to send SMS code.");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSendEmail = async () => {
    if (!challengeId) return;
    setLoading(true);
    setError(null);
    try {
      await beginEmail({ challenge_id: challengeId });
      setEmailSent(true);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.detail || "Failed to send email code.");
      } else {
        setError("Failed to send email code.");
      }
    } finally {
      setLoading(false);
    }
  };

  // ── Back to credentials ─────────────────────────────────────────

  const handleBack = () => {
    setStep("credentials");
    setChallengeId(null);
    setRequiredFactors([]);
    setPassedFactors({});
    setOtpValue("");
    setRecoveryCode("");
    setSmsSent(false);
    setEmailSent(false);
    setError(null);
  };

  // ── Available MFA methods (from required_factors) ───────────────

  const availableMethods: MfaMethod[] = React.useMemo(() => {
    const methods: MfaMethod[] = [];
    if (requiredFactors.includes("totp")) methods.push("totp");
    if (requiredFactors.includes("sms")) methods.push("sms");
    if (requiredFactors.includes("email")) methods.push("email");
    // Recovery is always available as a fallback
    methods.push("recovery");
    return methods;
  }, [requiredFactors]);

  // ── Render ──────────────────────────────────────────────────────

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-background via-background to-primary/5 p-4">
      {/* Background decoration */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -left-32 -top-32 h-96 w-96 rounded-full bg-primary/5 blur-3xl" />
        <div className="absolute -bottom-32 -right-32 h-96 w-96 rounded-full bg-primary/10 blur-3xl" />
      </div>

      <div className="relative w-full max-w-md">
        {/* Logo / Brand */}
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-primary text-primary-foreground shadow-lg">
            <Shield className="h-7 w-7" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">Welcome back</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Sign in to your account to continue
          </p>
        </div>

        <Card className="shadow-xl">
          {step === "credentials" ? (
            <form onSubmit={form.handleSubmit(handleCredentials)}>
              <CardHeader className="space-y-1">
                <CardTitle className="text-xl">Sign in</CardTitle>
                <CardDescription>
                  Enter your credentials to access your account
                </CardDescription>
              </CardHeader>

              <CardContent className="space-y-4">
                {error && (
                  <div className="rounded-lg border border-destructive/50 bg-destructive/10 px-4 py-3 text-sm text-destructive">
                    {error}
                  </div>
                )}

                <div className="space-y-2">
                  <Label htmlFor="username">Username</Label>
                  <Input
                    id="username"
                    placeholder="Enter your username"
                    autoComplete="username"
                    autoFocus
                    disabled={loading}
                    {...form.register("username")}
                  />
                  {form.formState.errors.username && (
                    <p className="text-xs text-destructive">
                      {form.formState.errors.username.message}
                    </p>
                  )}
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="password">Password</Label>
                    <Link
                      to="/password-recovery"
                      className="text-xs text-primary hover:underline"
                    >
                      Forgot password?
                    </Link>
                  </div>
                  <Input
                    id="password"
                    type="password"
                    placeholder="Enter your password"
                    autoComplete="current-password"
                    disabled={loading}
                    {...form.register("password")}
                  />
                  {form.formState.errors.password && (
                    <p className="text-xs text-destructive">
                      {form.formState.errors.password.message}
                    </p>
                  )}
                </div>
              </CardContent>

              <CardFooter>
                <Button type="submit" className="w-full" size="lg" disabled={loading}>
                  {loading && <Loader2 className="animate-spin" />}
                  Sign in
                </Button>
              </CardFooter>
            </form>
          ) : (
            /* ── MFA Challenge Step ─────────────────────────────── */
            <>
              <CardHeader className="space-y-1">
                <div className="flex items-center gap-2">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    onClick={handleBack}
                    disabled={loading}
                  >
                    <ArrowLeft className="h-4 w-4" />
                  </Button>
                  <div>
                    <CardTitle className="text-xl">Two-factor authentication</CardTitle>
                    <CardDescription>
                      {MFA_METHODS[activeMfa].description}
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>

              <CardContent className="space-y-6">
                {error && (
                  <div className="rounded-lg border border-destructive/50 bg-destructive/10 px-4 py-3 text-sm text-destructive">
                    {error}
                  </div>
                )}

                {/* Factor progress */}
                {requiredFactors.length > 1 && (
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    {requiredFactors.map((f) => (
                      <span
                        key={f}
                        className={
                          passedFactors[f]
                            ? "rounded-full bg-success/10 px-2 py-0.5 font-medium text-success"
                            : "rounded-full bg-muted px-2 py-0.5 font-medium text-muted-foreground"
                        }
                      >
                        {f.toUpperCase()} {passedFactors[f] ? "\u2713" : ""}
                      </span>
                    ))}
                  </div>
                )}

                {/* MFA method selector (if multiple methods available) */}
                {availableMethods.length > 1 && (
                  <div className="flex flex-wrap gap-2">
                    {availableMethods.map((method) => (
                      <Button
                        key={method}
                        variant={activeMfa === method ? "default" : "outline"}
                        size="sm"
                        onClick={() => {
                          setActiveMfa(method);
                          setOtpValue("");
                          setRecoveryCode("");
                          setError(null);
                        }}
                        disabled={loading}
                      >
                        {MFA_METHODS[method].icon}
                        <span className="ml-1">{MFA_METHODS[method].label}</span>
                      </Button>
                    ))}
                  </div>
                )}

                {/* ── TOTP input ──────────────────────────────── */}
                {activeMfa === "totp" && (
                  <div className="space-y-4">
                    <OtpInput
                      value={otpValue}
                      onChange={setOtpValue}
                      onComplete={(code) => handleMfaVerify(code)}
                      disabled={loading}
                      autoFocus
                    />
                  </div>
                )}

                {/* ── SMS input ───────────────────────────────── */}
                {activeMfa === "sms" && (
                  <div className="space-y-4">
                    {!smsSent ? (
                      <Button
                        variant="outline"
                        className="w-full"
                        onClick={handleSendSms}
                        disabled={loading}
                      >
                        {loading && <Loader2 className="animate-spin" />}
                        Send SMS Code
                      </Button>
                    ) : (
                      <>
                        <p className="text-sm text-muted-foreground">
                          A code has been sent to your phone. Enter it below.
                        </p>
                        <OtpInput
                          value={otpValue}
                          onChange={setOtpValue}
                          onComplete={(code) => handleMfaVerify(code)}
                          disabled={loading}
                          autoFocus
                        />
                        <Button
                          variant="link"
                          size="sm"
                          className="px-0"
                          onClick={handleSendSms}
                          disabled={loading}
                        >
                          Resend code
                        </Button>
                      </>
                    )}
                  </div>
                )}

                {/* ── Email input ─────────────────────────────── */}
                {activeMfa === "email" && (
                  <div className="space-y-4">
                    {!emailSent ? (
                      <Button
                        variant="outline"
                        className="w-full"
                        onClick={handleSendEmail}
                        disabled={loading}
                      >
                        {loading && <Loader2 className="animate-spin" />}
                        Send Email Code
                      </Button>
                    ) : (
                      <>
                        <p className="text-sm text-muted-foreground">
                          A code has been sent to your email. Enter it below.
                        </p>
                        <OtpInput
                          value={otpValue}
                          onChange={setOtpValue}
                          onComplete={(code) => handleMfaVerify(code)}
                          disabled={loading}
                          autoFocus
                        />
                        <Button
                          variant="link"
                          size="sm"
                          className="px-0"
                          onClick={handleSendEmail}
                          disabled={loading}
                        >
                          Resend code
                        </Button>
                      </>
                    )}
                  </div>
                )}

                {/* ── Recovery code input ─────────────────────── */}
                {activeMfa === "recovery" && (
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="recovery-code">Recovery Code</Label>
                      <Input
                        id="recovery-code"
                        placeholder="Enter your recovery code"
                        value={recoveryCode}
                        onChange={(e) => setRecoveryCode(e.target.value)}
                        disabled={loading}
                        autoFocus
                        className="font-mono"
                      />
                    </div>
                  </div>
                )}

                {/* Remember device */}
                <div className="flex items-center gap-2">
                  <Checkbox
                    id="remember"
                    checked={rememberDevice}
                    onCheckedChange={(checked) => setRememberDevice(checked === true)}
                    disabled={loading}
                  />
                  <Label htmlFor="remember" className="text-sm font-normal text-muted-foreground">
                    Remember this device for 30 days
                  </Label>
                </div>
              </CardContent>

              <CardFooter>
                {(activeMfa === "totp" || activeMfa === "recovery" ||
                  (activeMfa === "sms" && smsSent) ||
                  (activeMfa === "email" && emailSent)) && (
                  <Button
                    className="w-full"
                    size="lg"
                    onClick={() => handleMfaVerify()}
                    disabled={
                      loading ||
                      (activeMfa !== "recovery" && otpValue.length < 6) ||
                      (activeMfa === "recovery" && !recoveryCode.trim())
                    }
                  >
                    {loading && <Loader2 className="animate-spin" />}
                    Verify
                  </Button>
                )}
              </CardFooter>
            </>
          )}
        </Card>

        {/* Footer */}
        <p className="mt-6 text-center text-xs text-muted-foreground">
          Protected by multi-factor authentication
        </p>
      </div>
    </div>
  );
}
