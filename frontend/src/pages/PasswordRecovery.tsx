import * as React from "react";
import { Link, useNavigate } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Loader2, Shield, ArrowLeft, CheckCircle2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";

import { ApiError } from "@/api/client";
import { passwordRecoveryStart, passwordRecoveryConfirm } from "@/api/endpoints/auth";

// ─── Schemas ─────────────────────────────────────────────────────

const requestSchema = z.object({
  username: z.string().min(1, "Username is required"),
});

const confirmSchema = z.object({
  confirmation_code: z.string().min(1, "Confirmation code is required"),
  new_password: z.string().min(8, "Password must be at least 8 characters"),
  confirm_password: z.string().min(1, "Please confirm your password"),
}).refine((data) => data.new_password === data.confirm_password, {
  message: "Passwords don't match",
  path: ["confirm_password"],
});

type RequestForm = z.infer<typeof requestSchema>;
type ConfirmForm = z.infer<typeof confirmSchema>;
type RecoveryStep = "request" | "confirm" | "success";

// ─── Password Recovery Page ─────────────────────────────────────

export default function PasswordRecovery() {
  const navigate = useNavigate();

  const [step, setStep] = React.useState<RecoveryStep>("request");
  const [username, setUsername] = React.useState("");
  const [challengeId, setChallengeId] = React.useState<string | undefined>();
  const [deliveryInfo, setDeliveryInfo] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const requestForm = useForm<RequestForm>({
    resolver: zodResolver(requestSchema),
    defaultValues: { username: "" },
  });

  const confirmForm = useForm<ConfirmForm>({
    resolver: zodResolver(confirmSchema),
    defaultValues: { confirmation_code: "", new_password: "", confirm_password: "" },
  });

  // ── Step 1: Request recovery ────────────────────────────────────

  const handleRequest = async (data: RequestForm) => {
    setLoading(true);
    setError(null);
    try {
      const resp = await passwordRecoveryStart({ username: data.username });
      setUsername(data.username);
      setChallengeId(resp.challenge_id);

      if (resp.delivery_medium && resp.delivery_destination) {
        setDeliveryInfo(
          `A code has been sent via ${resp.delivery_medium} to ${resp.delivery_destination}`,
        );
      } else {
        setDeliveryInfo("A recovery code has been sent to your registered contact method.");
      }

      setStep("confirm");
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.detail || "Failed to start recovery. Please check your username.");
      } else {
        setError("An unexpected error occurred. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  // ── Step 2: Confirm new password ────────────────────────────────

  const handleConfirm = async (data: ConfirmForm) => {
    setLoading(true);
    setError(null);
    try {
      await passwordRecoveryConfirm({
        username,
        confirmation_code: data.confirmation_code,
        new_password: data.new_password,
        challenge_id: challengeId,
      });
      setStep("success");
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.detail || "Failed to reset password. Please check your code and try again.");
      } else {
        setError("An unexpected error occurred. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

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
          <h1 className="text-2xl font-bold tracking-tight">Password Recovery</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Reset your password to regain access
          </p>
        </div>

        <Card className="shadow-xl">
          {/* ── Step 1: Request ────────────────────────────── */}
          {step === "request" && (
            <form onSubmit={requestForm.handleSubmit(handleRequest)}>
              <CardHeader className="space-y-1">
                <div className="flex items-center gap-2">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    type="button"
                    onClick={() => navigate("/login")}
                  >
                    <ArrowLeft className="h-4 w-4" />
                  </Button>
                  <div>
                    <CardTitle className="text-xl">Forgot your password?</CardTitle>
                    <CardDescription>
                      Enter your username and we'll send you a recovery code
                    </CardDescription>
                  </div>
                </div>
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
                    {...requestForm.register("username")}
                  />
                  {requestForm.formState.errors.username && (
                    <p className="text-xs text-destructive">
                      {requestForm.formState.errors.username.message}
                    </p>
                  )}
                </div>
              </CardContent>

              <CardFooter className="flex flex-col gap-3">
                <Button type="submit" className="w-full" size="lg" disabled={loading}>
                  {loading && <Loader2 className="animate-spin" />}
                  Send Recovery Code
                </Button>
                <Link
                  to="/login"
                  className="text-sm text-muted-foreground hover:text-foreground hover:underline"
                >
                  Back to sign in
                </Link>
              </CardFooter>
            </form>
          )}

          {/* ── Step 2: Confirm ───────────────────────────── */}
          {step === "confirm" && (
            <form onSubmit={confirmForm.handleSubmit(handleConfirm)}>
              <CardHeader className="space-y-1">
                <div className="flex items-center gap-2">
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    type="button"
                    onClick={() => {
                      setStep("request");
                      setError(null);
                    }}
                  >
                    <ArrowLeft className="h-4 w-4" />
                  </Button>
                  <div>
                    <CardTitle className="text-xl">Reset your password</CardTitle>
                    <CardDescription>
                      {deliveryInfo ?? "Enter the code you received and choose a new password"}
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>

              <CardContent className="space-y-4">
                {error && (
                  <div className="rounded-lg border border-destructive/50 bg-destructive/10 px-4 py-3 text-sm text-destructive">
                    {error}
                  </div>
                )}

                <div className="space-y-2">
                  <Label htmlFor="code">Confirmation Code</Label>
                  <Input
                    id="code"
                    placeholder="Enter the code"
                    autoFocus
                    disabled={loading}
                    className="font-mono"
                    {...confirmForm.register("confirmation_code")}
                  />
                  {confirmForm.formState.errors.confirmation_code && (
                    <p className="text-xs text-destructive">
                      {confirmForm.formState.errors.confirmation_code.message}
                    </p>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="new-password">New Password</Label>
                  <Input
                    id="new-password"
                    type="password"
                    placeholder="Enter new password"
                    autoComplete="new-password"
                    disabled={loading}
                    {...confirmForm.register("new_password")}
                  />
                  {confirmForm.formState.errors.new_password && (
                    <p className="text-xs text-destructive">
                      {confirmForm.formState.errors.new_password.message}
                    </p>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="confirm-password">Confirm Password</Label>
                  <Input
                    id="confirm-password"
                    type="password"
                    placeholder="Confirm new password"
                    autoComplete="new-password"
                    disabled={loading}
                    {...confirmForm.register("confirm_password")}
                  />
                  {confirmForm.formState.errors.confirm_password && (
                    <p className="text-xs text-destructive">
                      {confirmForm.formState.errors.confirm_password.message}
                    </p>
                  )}
                </div>
              </CardContent>

              <CardFooter>
                <Button type="submit" className="w-full" size="lg" disabled={loading}>
                  {loading && <Loader2 className="animate-spin" />}
                  Reset Password
                </Button>
              </CardFooter>
            </form>
          )}

          {/* ── Step 3: Success ───────────────────────────── */}
          {step === "success" && (
            <>
              <CardHeader className="items-center text-center">
                <div className="mb-2 flex h-12 w-12 items-center justify-center rounded-full bg-success/10">
                  <CheckCircle2 className="h-6 w-6 text-success" />
                </div>
                <CardTitle className="text-xl">Password reset successful</CardTitle>
                <CardDescription>
                  Your password has been updated. You can now sign in with your new password.
                </CardDescription>
              </CardHeader>

              <CardFooter className="justify-center">
                <Button asChild size="lg">
                  <Link to="/login">Back to sign in</Link>
                </Button>
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
