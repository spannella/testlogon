import * as React from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { AlertCircle, ArrowLeft, CheckCircle2, Circle, Eye, EyeOff, HelpCircle, Loader2, Shield, XCircle } from "lucide-react";
import { PageMeta } from "@/components/shared/PageMeta";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { OtpInput } from "@/components/ui/otp-input";

import { ApiError } from "@/api/client";
import { getMe, registerConfirm, registerEmailCheck, registerResend, registerStart } from "@/api/endpoints/auth";
import {
  beginSmsEnrollment,
  beginTotpEnrollment,
  confirmSmsEnrollment,
  confirmTotpEnrollment,
} from "@/api/endpoints/account";
import { useAuthStore } from "@/stores/authStore";

const registerSchema = z.object({
  full_name: z.string().trim().min(1, "Full name is required"),
  email: z.string().trim().email("Enter a valid email"),
  password: z.string()
    .min(12, "Password must be at least 12 characters")
    .max(128, "Password must be 128 characters or fewer")
    .regex(/[a-z]/, "Password must contain a lowercase letter")
    .regex(/[A-Z]/, "Password must contain an uppercase letter")
    .regex(/\d/, "Password must contain a number")
    .regex(/[^A-Za-z0-9]/, "Password must contain a special character"),
  confirm_password: z.string().min(1, "Please confirm your password"),
  phone: z.string().trim().optional(),
  enable_sms_mfa: z.boolean().optional(),
  enable_totp_mfa: z.boolean().optional(),
}).superRefine((data, ctx) => {
  if (data.password !== data.confirm_password) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Passwords don't match",
      path: ["confirm_password"],
    });
  }
  if (data.enable_sms_mfa && !data.phone?.trim()) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Phone number is required for SMS verification",
      path: ["phone"],
    });
  }
});

const confirmSchema = z.object({
  confirmation_code: z.string().min(1, "Confirmation code is required"),
});

type RegisterForm = z.infer<typeof registerSchema>;
type ConfirmForm = z.infer<typeof confirmSchema>;
type RegisterStep = "start" | "verify" | "mfa" | "success";
type PendingRegistration = {
  email: string;
  enable_sms_mfa: boolean;
  enable_totp_mfa: boolean;
  phone?: string;
};

const REGISTER_STORAGE_KEY = "register-pending";
const EMAIL_CHECK_TIMEOUT_MS = 8000;

export default function Register() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { login } = useAuthStore();
  const [error, setError] = React.useState<string | null>(null);
  const [message, setMessage] = React.useState<string | null>(null);
  const [deliveryInfo, setDeliveryInfo] = React.useState<string | null>(null);
  const [step, setStep] = React.useState<RegisterStep>("start");
  const [registeredEmail, setRegisteredEmail] = React.useState("");
  const [pendingPhone, setPendingPhone] = React.useState<string | undefined>();
  const [pendingSmsMfa, setPendingSmsMfa] = React.useState(false);
  const [pendingTotpMfa, setPendingTotpMfa] = React.useState(false);
  const [startLoading, setStartLoading] = React.useState(false);
  const [confirmLoading, setConfirmLoading] = React.useState(false);
  const [resendLoading, setResendLoading] = React.useState(false);
  const [mfaLoading, setMfaLoading] = React.useState(false);
  const [emailStatus, setEmailStatus] = React.useState<
    "idle" | "checking" | "available" | "unavailable" | "unavailable_unverified" | "invalid" | "error" | "rate_limited"
  >("idle");
  const [mfaError, setMfaError] = React.useState<string | null>(null);
  const [smsChallengeId, setSmsChallengeId] = React.useState<string | null>(null);
  const [smsSentTo, setSmsSentTo] = React.useState<string[]>([]);
  const [smsCode, setSmsCode] = React.useState("");
  const [smsVerified, setSmsVerified] = React.useState(false);
  const [totpEnrollData, setTotpEnrollData] = React.useState<{ device_id: string; secret: string; qr_code_uri: string } | null>(null);
  const [totpCode, setTotpCode] = React.useState("");
  const [totpCode2, setTotpCode2] = React.useState("");
  const [totpVerified, setTotpVerified] = React.useState(false);
  const [recoveryCodes, setRecoveryCodes] = React.useState<string[]>([]);
  const [showPassword, setShowPassword] = React.useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = React.useState(false);

  const form = useForm<RegisterForm>({
    resolver: zodResolver(registerSchema),
    mode: "onChange",
    defaultValues: {
      full_name: "",
      email: "",
      password: "",
      confirm_password: "",
      phone: "",
      enable_sms_mfa: false,
      enable_totp_mfa: false,
    },
  });

  const confirmForm = useForm<ConfirmForm>({
    resolver: zodResolver(confirmSchema),
    defaultValues: {
      confirmation_code: "",
    },
  });

  const enableSmsMfa = form.watch("enable_sms_mfa");
  const fullNameValue = form.watch("full_name");
  const emailValue = form.watch("email");
  const passwordValue = form.watch("password");
  const confirmPasswordValue = form.watch("confirm_password");

  React.useEffect(() => {
    if (form.formState.touchedFields.confirm_password) {
      void form.trigger("confirm_password");
    }
  }, [passwordValue, form]);

  const passwordRequirements = [
    { id: "length", label: "At least 12 characters", met: passwordValue.length >= 12 },
    { id: "max", label: "No more than 128 characters", met: passwordValue.length <= 128 },
    { id: "lower", label: "One lowercase letter (a–z)", met: /[a-z]/.test(passwordValue) },
    { id: "upper", label: "One uppercase letter (A–Z)", met: /[A-Z]/.test(passwordValue) },
    { id: "digit", label: "One number (0–9)", met: /\d/.test(passwordValue) },
    { id: "symbol", label: "One special character (!@#$ …)", met: /[^A-Za-z0-9]/.test(passwordValue) },
  ];
  const passwordClassesUsed = [
    /[a-z]/.test(passwordValue),
    /[A-Z]/.test(passwordValue),
    /\d/.test(passwordValue),
    /[^A-Za-z0-9]/.test(passwordValue),
  ].filter(Boolean).length;
  const passwordStrengthScore = Math.min(
    5,
    (passwordValue.length >= 8 ? 1 : 0)
      + (passwordValue.length >= 12 ? 1 : 0)
      + (passwordValue.length >= 16 ? 1 : 0)
      + (passwordClassesUsed >= 2 ? 1 : 0)
      + (passwordClassesUsed >= 3 ? 1 : 0),
  );
  const passwordStrengthLevels = [
    { label: "Very weak", colorClass: "bg-red-500" },
    { label: "Weak", colorClass: "bg-orange-500" },
    { label: "Fair", colorClass: "bg-yellow-400" },
    { label: "Good", colorClass: "bg-lime-500" },
    { label: "Strong", colorClass: "bg-green-600" },
  ] as const;
  const activePasswordStrength = passwordStrengthLevels[Math.max(passwordStrengthScore - 1, 0)] ?? passwordStrengthLevels[0];
  const passwordsMatch = confirmPasswordValue.length > 0 && passwordValue === confirmPasswordValue;
  const hasPasswordIssues = !passwordRequirements.every((req) => req.met) || !passwordsMatch;
  const isFullNameValid = fullNameValue.trim().length > 0 && !form.formState.errors.full_name;
  const isPasswordStrong = passwordRequirements.every((req) => req.met) && passwordsMatch;
  const isEmailChecking = emailStatus === "checking";
  const isSubmitDisabled = startLoading
    || isEmailChecking
    || hasPasswordIssues
    || emailStatus === "invalid"
    || emailStatus === "unavailable"
    || emailStatus === "unavailable_unverified"
    || emailStatus === "rate_limited";

  React.useEffect(() => {
    const emailParam = searchParams.get("email");
    const codeParam = searchParams.get("code") ?? searchParams.get("confirmation_code");

    if (emailParam) {
      setRegisteredEmail(emailParam);
      setPendingPhone(undefined);
      setPendingSmsMfa(false);
      setPendingTotpMfa(false);
      setDeliveryInfo("Enter the verification code we sent to finish registration.");
      setStep("verify");
      if (codeParam) {
        confirmForm.setValue("confirmation_code", codeParam);
      }
      return;
    }

    const stored = localStorage.getItem(REGISTER_STORAGE_KEY);
    if (!stored) {
      return;
    }
    try {
      const parsed = JSON.parse(stored) as PendingRegistration;
      if (!parsed?.email) {
        return;
      }
      setRegisteredEmail(parsed.email);
      setPendingPhone(parsed.phone);
      setPendingSmsMfa(parsed.enable_sms_mfa ?? false);
      setPendingTotpMfa(parsed.enable_totp_mfa ?? false);
      setDeliveryInfo("Enter the verification code we sent to finish registration.");
      setStep("verify");
    } catch {
      localStorage.removeItem(REGISTER_STORAGE_KEY);
    }
  }, [confirmForm, searchParams]);

  React.useEffect(() => {
    if (!emailValue) {
      setEmailStatus("idle");
      return;
    }
    const trimmed = emailValue.trim();
    const emailValid = z.string().email().safeParse(trimmed).success;
    if (!emailValid) {
      setEmailStatus("invalid");
      return;
    }
    let isActive = true;
    let didTimeout = false;
    setEmailStatus("checking");
    const timer = window.setTimeout(() => {
      const timeoutTimer = window.setTimeout(() => {
        didTimeout = true;
        if (!isActive) {
          return;
        }
        setEmailStatus("error");
      }, EMAIL_CHECK_TIMEOUT_MS);

      registerEmailCheck({ email: trimmed })
        .then((data) => {
          window.clearTimeout(timeoutTimer);
          if (!isActive || didTimeout) {
            return;
          }
          if (data.available) {
            setEmailStatus("available");
          } else if (data.unverified) {
            setEmailStatus("unavailable_unverified");
          } else {
            setEmailStatus("unavailable");
          }
        })
        .catch((err) => {
          window.clearTimeout(timeoutTimer);
          if (!isActive || didTimeout) {
            return;
          }
          if (err instanceof ApiError && err.status === 429) {
            setEmailStatus("rate_limited");
          } else if (err instanceof ApiError && err.status === 400) {
            setEmailStatus("invalid");
          } else {
            setEmailStatus("error");
          }
        });
    }, 400);
    return () => {
      isActive = false;
      window.clearTimeout(timer);
    };
  }, [emailValue]);

  const handleStart = async (data: RegisterForm) => {
    setStartLoading(true);
    setMessage(null);
    setError(null);
    setDeliveryInfo(null);
    const trimmedFullName = data.full_name.trim();
    const trimmedEmail = data.email.trim();
    const trimmedPhone = data.phone?.trim();
    try {
      const resp = await registerStart({
        full_name: trimmedFullName,
        email: trimmedEmail,
        password: data.password,
        confirm_password: data.confirm_password,
        phone: data.enable_sms_mfa ? trimmedPhone : undefined,
        enable_sms_mfa: !!data.enable_sms_mfa,
        enable_totp_mfa: !!data.enable_totp_mfa,
      });
      setRegisteredEmail(trimmedEmail);
      if (resp.verification_required) {
        const pending: PendingRegistration = {
          email: trimmedEmail,
          enable_sms_mfa: !!data.enable_sms_mfa,
          enable_totp_mfa: !!data.enable_totp_mfa,
          phone: data.enable_sms_mfa ? trimmedPhone : undefined,
        };
        localStorage.setItem(REGISTER_STORAGE_KEY, JSON.stringify(pending));
        setPendingPhone(pending.phone);
        setPendingSmsMfa(pending.enable_sms_mfa);
        setPendingTotpMfa(pending.enable_totp_mfa);
        if (resp.delivery_medium && resp.delivery_destination) {
          setDeliveryInfo(
            `We sent a verification code via ${resp.delivery_medium} to ${resp.delivery_destination}.`,
          );
        } else {
          setDeliveryInfo("We sent a verification code to your email.");
        }
        setStep("verify");
      } else {
        if (resp.session_id) {
          const me = await getMe();
          login(me.user_sub, "");
          navigate("/", { replace: true });
          return;
        }
        setMessage("Registration complete! You can now sign in.");
        setStep("success");
      }
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 429) {
          setError(err.detail || "Too many registration attempts. Please wait and try again.");
        } else {
          setError(err.detail || "Registration failed. Please check your details and try again.");
        }
      } else {
        setError("An unexpected error occurred. Please try again.");
      }
    } finally {
      setStartLoading(false);
    }
  };

  const handleConfirm = async (data: ConfirmForm) => {
    setConfirmLoading(true);
    setError(null);
    try {
      const resp = await registerConfirm({
        email: registeredEmail,
        confirmation_code: data.confirmation_code,
      });
      localStorage.removeItem(REGISTER_STORAGE_KEY);
      const mfaSetup = resp.mfa_setup ?? [];
      if (resp.session_id) {
        const me = await getMe();
        login(me.user_sub, "");
        if (mfaSetup.length > 0) {
          setPendingSmsMfa(mfaSetup.includes("sms") || pendingSmsMfa);
          setPendingTotpMfa(mfaSetup.includes("totp") || pendingTotpMfa);
          setPendingPhone(resp.sms_phone ?? pendingPhone);
          setStep("mfa");
          return;
        }
        navigate("/", { replace: true });
        return;
      }
      setMessage("Registration verified! You can now sign in.");
      setStep("success");
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.detail || "Verification failed. Please check the code and try again.");
      } else {
        setError("An unexpected error occurred. Please try again.");
      }
    } finally {
      setConfirmLoading(false);
    }
  };

  const handleResend = async () => {
    if (!registeredEmail) {
      setError("Please return to registration to restart the flow.");
      return;
    }
    setResendLoading(true);
    setError(null);
    try {
      const resp = await registerResend({
        email: registeredEmail,
        delivery_method: "email",
        phone: pendingSmsMfa ? pendingPhone : undefined,
        enable_sms_mfa: pendingSmsMfa,
        enable_totp_mfa: pendingTotpMfa,
      });
      if (resp.delivery_medium && resp.delivery_destination) {
        setDeliveryInfo(
          `We sent a verification code via ${resp.delivery_medium} to ${resp.delivery_destination}.`,
        );
      } else {
        setDeliveryInfo("We sent a verification code to your email.");
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.detail || "Failed to resend verification code.");
      } else {
        setError("An unexpected error occurred. Please try again.");
      }
    } finally {
      setResendLoading(false);
    }
  };

  const handleResendFromCheck = async () => {
    const email = form.getValues("email").trim();
    if (!email) {
      setError("Enter your email address first.");
      return;
    }
    setResendLoading(true);
    setError(null);
    try {
      const resp = await registerResend({ email, delivery_method: "email" });
      setRegisteredEmail(email);
      if (resp.delivery_medium && resp.delivery_destination) {
        setDeliveryInfo(
          `We sent a new verification code via ${resp.delivery_medium} to ${resp.delivery_destination}.`,
        );
      } else {
        setDeliveryInfo("We sent a new verification code to your email.");
      }
      setStep("verify");
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.detail || "Could not resend verification code. Please try again.");
      } else {
        setError("Could not resend verification code. Please try again.");
      }
    } finally {
      setResendLoading(false);
    }
  };

  React.useEffect(() => {
    if (step !== "mfa" || !pendingTotpMfa || totpEnrollData || totpVerified) {
      return;
    }
    let isMounted = true;
    setMfaLoading(true);
    setMfaError(null);
    beginTotpEnrollment({ label: "Authenticator App" })
      .then((resp) => {
        if (!isMounted) {
          return;
        }
        setTotpEnrollData(resp);
      })
      .catch((err) => {
        if (!isMounted) {
          return;
        }
        if (err instanceof ApiError) {
          setMfaError(err.detail || "Failed to start TOTP enrollment.");
        } else {
          setMfaError("Failed to start TOTP enrollment.");
        }
      })
      .finally(() => {
        if (isMounted) {
          setMfaLoading(false);
        }
      });
    return () => {
      isMounted = false;
    };
  }, [pendingTotpMfa, step, totpEnrollData, totpVerified]);

  const handleSmsBegin = async () => {
    if (!pendingPhone) {
      setMfaError("Phone number is required for SMS verification.");
      return;
    }
    setMfaLoading(true);
    setMfaError(null);
    try {
      const resp = await beginSmsEnrollment({ phone_e164: pendingPhone, label: "Primary phone" });
      setSmsChallengeId(resp.challenge_id);
      setSmsSentTo(resp.sent_to);
    } catch (err) {
      if (err instanceof ApiError) {
        setMfaError(err.detail || "Failed to send SMS verification.");
      } else {
        setMfaError("Failed to send SMS verification.");
      }
    } finally {
      setMfaLoading(false);
    }
  };

  const handleSmsConfirm = async (codeOverride?: string) => {
    if (!smsChallengeId) {
      setMfaError("Send a verification code first.");
      return;
    }
    const finalCode = codeOverride ?? smsCode;
    setMfaLoading(true);
    setMfaError(null);
    try {
      const resp = await confirmSmsEnrollment({ challenge_id: smsChallengeId, code: finalCode });
      setSmsVerified(true);
      if (resp.recovery_codes?.length) setRecoveryCodes(resp.recovery_codes);
    } catch (err) {
      if (err instanceof ApiError) {
        setMfaError(err.detail || "Invalid SMS code.");
      } else {
        setMfaError("Invalid SMS code.");
      }
    } finally {
      setMfaLoading(false);
    }
  };

  const handleTotpConfirm = async (code2Override?: string) => {
    if (!totpEnrollData) {
      return;
    }
    const finalCode2 = code2Override ?? totpCode2;
    setMfaLoading(true);
    setMfaError(null);
    try {
      const resp = await confirmTotpEnrollment({ device_id: totpEnrollData.device_id, totp_code: totpCode, totp_code2: finalCode2 });
      setTotpVerified(true);
      if (resp.recovery_codes?.length) setRecoveryCodes(resp.recovery_codes);
    } catch (err) {
      if (err instanceof ApiError) {
        setMfaError(err.detail || "Invalid TOTP code.");
      } else {
        setMfaError("Invalid TOTP code.");
      }
    } finally {
      setMfaLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-background via-background to-primary/5 p-4">
      <PageMeta title="Create Account" />
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -left-32 -top-32 h-96 w-96 rounded-full bg-primary/5 blur-3xl" />
        <div className="absolute -bottom-32 -right-32 h-96 w-96 rounded-full bg-primary/10 blur-3xl" />
      </div>

      <div className="relative w-full max-w-md">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-primary text-primary-foreground shadow-lg">
            <Shield className="h-7 w-7" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">Create your account</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Set up your access details to get started
          </p>
        </div>

        <Card className="shadow-xl">
          {step === "start" && (
            <form onSubmit={form.handleSubmit(handleStart)}>
              <CardHeader className="space-y-1">
                <CardTitle className="text-xl">Register</CardTitle>
                <CardDescription>
                  Use your work email to request access
                </CardDescription>
              </CardHeader>

              <CardContent className="space-y-4">
                <div className="rounded-lg border border-muted bg-muted/20 px-4 py-3 text-xs text-muted-foreground">
                  <div className="flex items-start justify-between gap-3">
                    <p className="font-medium text-foreground">Security reminder</p>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <button
                          type="button"
                          className="text-muted-foreground transition-colors hover:text-foreground"
                          aria-label="Why this matters"
                        >
                          <HelpCircle className="h-4 w-4" />
                        </button>
                      </TooltipTrigger>
                      <TooltipContent className="max-w-xs text-pretty">
                        Attackers often impersonate registration pages. Always verify the hostname and HTTPS
                        certificate so you don’t share personal details on a phishing site.
                      </TooltipContent>
                    </Tooltip>
                  </div>
                  <p>
                    Confirm the URL matches
                    {" "}
                    <span className="font-semibold">
                      {(import.meta as any).env?.VITE_PUBLIC_HOSTNAME ?? window.location.hostname}
                    </span>
                    {" "}
                    and you see a valid HTTPS certificate before continuing.
                  </p>
                </div>
                {error && (
                  <div className="rounded-lg border border-destructive/50 bg-destructive/10 px-4 py-3 text-sm text-destructive">
                    {error}
                  </div>
                )}
                {message && (
                  <div className="rounded-lg border border-primary/30 bg-primary/5 px-4 py-3 text-sm text-primary">
                    {message}
                  </div>
                )}

                <div className="space-y-2">
                  <Label htmlFor="full_name">Full name</Label>
                  <Input
                    id="full_name"
                    placeholder="Jane Doe"
                    autoComplete="name"
                    {...form.register("full_name")}
                  />
                  {form.formState.errors.full_name && (
                    <p className="text-xs text-destructive">
                      {form.formState.errors.full_name.message}
                    </p>
                  )}
                  {isFullNameValid && (
                    <p className="flex items-center gap-1 text-xs text-emerald-600">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      Looks good.
                    </p>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <Input
                    id="email"
                    placeholder="you@company.com"
                    autoComplete="email"
                    type="email"
                    {...form.register("email")}
                  />
                  {form.formState.errors.email && (
                    <p className="text-xs text-destructive">
                      {form.formState.errors.email.message}
                    </p>
                  )}
                  {!form.formState.errors.email && emailStatus === "checking" && (
                    <p className="text-xs text-muted-foreground">Checking email availability…</p>
                  )}
                  {!form.formState.errors.email && emailStatus === "available" && (
                    <p className="flex items-center gap-1 text-xs text-emerald-600">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      Email looks valid.
                    </p>
                  )}
                  {!form.formState.errors.email && emailStatus === "unavailable" && (
                    <p className="flex items-center gap-1 text-xs text-destructive">
                      <XCircle className="h-3.5 w-3.5" />
                      <span>
                        An account with this email already exists.{" "}
                        <Link to="/login" className="underline">Sign in instead?</Link>
                      </span>
                    </p>
                  )}
                  {!form.formState.errors.email && emailStatus === "unavailable_unverified" && (
                    <div
                      role="alert"
                      className="flex flex-col gap-2 rounded-md border border-amber-300 bg-amber-50 p-3 text-xs"
                    >
                      <p className="flex items-center gap-1 font-medium text-amber-800">
                        <AlertCircle className="h-3.5 w-3.5" />
                        A verification is pending for this email.
                      </p>
                      <p className="text-muted-foreground">
                        We can resend the verification code so you can finish setting up your account.
                      </p>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        disabled={resendLoading}
                        onClick={() => { void handleResendFromCheck(); }}
                      >
                        {resendLoading ? "Sending…" : "Resend verification code"}
                      </Button>
                    </div>
                  )}
                  {!form.formState.errors.email && emailStatus === "rate_limited" && (
                    <p className="flex items-center gap-1 text-xs text-destructive">
                      <XCircle className="h-3.5 w-3.5" />
                      Too many checks. Please wait before trying again.
                    </p>
                  )}
                  {!form.formState.errors.email && emailStatus === "error" && (
                    <p className="text-xs text-destructive">
                      Unable to check email availability. Please try again.
                    </p>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="password">Password</Label>
                  <div className="relative">
                    <Input
                      id="password"
                      type={showPassword ? "text" : "password"}
                      placeholder="Create a password"
                      autoComplete="new-password"
                      className="pr-10"
                      {...form.register("password")}
                    />
                    <button
                      type="button"
                      aria-label={showPassword ? "Hide password" : "Show password"}
                      className="absolute inset-y-0 right-0 flex items-center px-3 text-muted-foreground hover:text-foreground"
                      onClick={() => setShowPassword((prev) => !prev)}
                    >
                      {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                  {form.formState.errors.password && (
                    <p className="text-xs text-destructive">
                      {form.formState.errors.password.message}
                    </p>
                  )}
                </div>

                <div className="space-y-2">
                  <Label htmlFor="confirm_password">Confirm password</Label>
                  <div className="relative">
                    <Input
                      id="confirm_password"
                      type={showConfirmPassword ? "text" : "password"}
                      placeholder="Re-enter your password"
                      autoComplete="new-password"
                      className="pr-10"
                      {...form.register("confirm_password")}
                    />
                    <button
                      type="button"
                      aria-label={showConfirmPassword ? "Hide confirm password" : "Show confirm password"}
                      className="absolute inset-y-0 right-0 flex items-center px-3 text-muted-foreground hover:text-foreground"
                      onClick={() => setShowConfirmPassword((prev) => !prev)}
                    >
                      {showConfirmPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                  {form.formState.errors.confirm_password && (
                    <p className="text-xs text-destructive">
                      {form.formState.errors.confirm_password.message}
                    </p>
                  )}
                  {isPasswordStrong && (
                    <p className="flex items-center gap-1 text-xs text-emerald-600">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      Passwords look good.
                    </p>
                  )}
                </div>

                <div className="space-y-2 rounded-lg border border-muted bg-muted/20 p-3">
                  <div className="flex items-center justify-between gap-2 text-sm font-medium">
                    <span>Password strength</span>
                    <span className="text-xs text-muted-foreground">{activePasswordStrength.label}</span>
                  </div>
                  <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                    <div
                      className={`h-full transition-all ${activePasswordStrength.colorClass}`}
                      style={{ width: passwordValue.length === 0 ? "0%" : `${Math.max(passwordStrengthScore, 1) * 20}%` }}
                    />
                  </div>
                  <div className="text-sm font-medium">Password requirements</div>
                  <ul className="space-y-1 text-xs">
                    {passwordRequirements.map((req) => (
                      <li
                        key={req.id}
                        className={`flex items-center gap-1 ${req.met ? "text-emerald-600" : "text-muted-foreground"}`}
                      >
                        {req.met ? (
                          <CheckCircle2 className="h-3.5 w-3.5" />
                        ) : (
                          <Circle className="h-3.5 w-3.5" />
                        )}
                        {req.label}
                      </li>
                    ))}
                    <li
                      className={`flex items-center gap-1 ${
                        confirmPasswordValue.length === 0
                          ? "text-muted-foreground"
                          : passwordsMatch
                          ? "text-emerald-600"
                          : "text-destructive"
                      }`}
                    >
                      {confirmPasswordValue.length === 0 ? (
                        <Circle className="h-3.5 w-3.5" />
                      ) : passwordsMatch ? (
                        <CheckCircle2 className="h-3.5 w-3.5" />
                      ) : (
                        <XCircle className="h-3.5 w-3.5" />
                      )}
                      Passwords match
                    </li>
                  </ul>
                </div>

                <div className="space-y-3 rounded-lg border border-muted bg-muted/20 p-3">
                  <div className="text-sm font-medium">Optional security upgrades</div>
                  <label className="flex items-start gap-2 text-sm">
                    <input type="checkbox" className="mt-1" {...form.register("enable_totp_mfa")} />
                    <span className="flex flex-col">
                      <span className="flex items-center gap-2">
                        Authenticator app (TOTP)
                        <span className="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] font-semibold text-primary">
                          Recommended
                        </span>
                      </span>
                      <span className="text-xs text-muted-foreground">
                        Most secure and works offline.
                      </span>
                    </span>
                  </label>
                  <label className="flex items-start gap-2 text-sm">
                    <input type="checkbox" className="mt-1" {...form.register("enable_sms_mfa")} />
                    <span className="flex flex-col">
                      <span>SMS verification</span>
                      <span className="text-xs text-muted-foreground">
                        Useful backup, but less secure than an authenticator app.
                      </span>
                    </span>
                  </label>
                </div>

                {enableSmsMfa && (
                  <div className="space-y-2">
                    <Label htmlFor="phone">Phone number for SMS</Label>
                    <Input
                      id="phone"
                      placeholder="+1 555 123 4567"
                      autoComplete="tel"
                      type="tel"
                      {...form.register("phone")}
                    />
                    {form.formState.errors.phone && (
                      <p className="text-xs text-destructive">
                        {form.formState.errors.phone.message}
                      </p>
                    )}
                  </div>
                )}
              </CardContent>

              <CardFooter className="flex flex-col gap-4">
                <Button type="submit" className="w-full" size="lg" disabled={isSubmitDisabled}>
                  {startLoading ? (
                    <span className="flex items-center justify-center gap-2">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Requesting access
                    </span>
                  ) : (
                    "Request access"
                  )}
                </Button>
                <div className="flex w-full items-center justify-center gap-2 text-xs text-muted-foreground">
                  <ArrowLeft className="h-3.5 w-3.5" />
                  <button
                    type="button"
                    className="text-primary hover:underline"
                    onClick={() => navigate("/login")}
                  >
                    Back to sign in
                  </button>
                </div>
                <div className="text-center text-xs text-muted-foreground">
                  Already have an account?{" "}
                  <Link to="/login" className="text-primary hover:underline">Sign in</Link>
                </div>
              </CardFooter>
            </form>
          )}

          {step === "verify" && (
            <form onSubmit={confirmForm.handleSubmit(handleConfirm)}>
              <CardHeader className="space-y-1">
                <CardTitle className="text-xl">Verify your account</CardTitle>
                <CardDescription>
                  Enter the confirmation code to activate your account.
                </CardDescription>
              </CardHeader>

              <CardContent className="space-y-4">
                {deliveryInfo && (
                  <div className="rounded-lg border border-primary/30 bg-primary/5 px-4 py-3 text-sm text-primary">
                    {deliveryInfo}
                  </div>
                )}
                {error && (
                  <div className="rounded-lg border border-destructive/50 bg-destructive/10 px-4 py-3 text-sm text-destructive">
                    {error}
                  </div>
                )}

                <div className="space-y-2">
                  <Label>Confirmation code</Label>
                  <div className="flex justify-center">
                    <OtpInput
                      value={confirmForm.watch("confirmation_code")}
                      onChange={(val) => confirmForm.setValue("confirmation_code", val, { shouldValidate: true })}
                      onComplete={() => confirmForm.handleSubmit(handleConfirm)()}
                      disabled={confirmLoading}
                      autoFocus
                    />
                  </div>
                  {confirmForm.formState.errors.confirmation_code && (
                    <p className="text-xs text-destructive">
                      {confirmForm.formState.errors.confirmation_code.message}
                    </p>
                  )}
                </div>
              </CardContent>

              <CardFooter className="flex flex-col gap-4">
                <Button type="submit" className="w-full" size="lg" disabled={confirmLoading}>
                  {confirmLoading ? (
                    <span className="flex items-center justify-center gap-2">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Verifying
                    </span>
                  ) : (
                    "Verify account"
                  )}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  className="w-full"
                  disabled={resendLoading}
                  onClick={() => { void handleResend(); }}
                >
                  {resendLoading ? "Resending..." : "Resend code"}
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  className="w-full"
                  onClick={() => {
                    localStorage.removeItem(REGISTER_STORAGE_KEY);
                    setError(null);
                    setStep("start");
                  }}
                >
                  Back to registration
                </Button>
              </CardFooter>
            </form>
          )}

          {step === "mfa" && (
            <div>
              <CardHeader className="space-y-1">
                <CardTitle className="text-xl">Secure your account</CardTitle>
                <CardDescription>
                  Complete your selected security steps before continuing.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                {mfaError && (
                  <div className="rounded-lg border border-destructive/50 bg-destructive/10 px-4 py-3 text-sm text-destructive">
                    {mfaError}
                  </div>
                )}

                {pendingSmsMfa && (
                  <div className="space-y-3 rounded-lg border border-border p-4">
                    <div>
                      <p className="text-sm font-medium">SMS verification</p>
                      <p className="text-xs text-muted-foreground">
                        Verify your phone number to enable SMS security prompts.
                      </p>
                    </div>
                    <div className="flex flex-col gap-3">
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => { void handleSmsBegin(); }}
                        disabled={mfaLoading || smsVerified}
                      >
                        {smsVerified ? "Phone verified" : "Send verification code"}
                      </Button>
                      {smsSentTo.length > 0 && (
                        <p className="text-xs text-muted-foreground">
                          Code sent to {smsSentTo.join(", ")}
                        </p>
                      )}
                      {!smsVerified && (
                        <div className="space-y-3">
                          <Label>SMS code</Label>
                          <div className="flex justify-center">
                            <OtpInput
                              value={smsCode}
                              onChange={setSmsCode}
                              onComplete={(val) => { void handleSmsConfirm(val); }}
                              disabled={mfaLoading}
                              autoFocus
                            />
                          </div>
                          <Button
                            type="button"
                            className="w-full"
                            onClick={() => { void handleSmsConfirm(smsCode); }}
                            disabled={mfaLoading || smsCode.length !== 6}
                          >
                            Verify SMS code
                          </Button>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {pendingTotpMfa && (
                  <div className="space-y-3 rounded-lg border border-border p-4">
                    <div>
                      <p className="text-sm font-medium">Authenticator app</p>
                      <p className="text-xs text-muted-foreground">
                        Scan the QR code in your authenticator app and confirm with a 6-digit code.
                      </p>
                    </div>
                    {mfaLoading && !totpEnrollData && (
                      <p className="text-xs text-muted-foreground">Preparing QR code…</p>
                    )}
                    {totpEnrollData && (
                      <div className="space-y-3">
                        <div className="flex justify-center rounded-lg border bg-white p-3">
                          <img src={totpEnrollData.qr_code_uri} alt="TOTP QR code" className="h-40 w-40" />
                        </div>
                        <div>
                          <Label className="text-xs text-muted-foreground">Manual entry key</Label>
                          <code className="mt-1 block break-all rounded bg-muted px-2 py-1 text-xs font-mono">
                            {totpEnrollData.secret}
                          </code>
                        </div>
                        {!totpVerified && (
                          <div className="space-y-3">
                            <div>
                              <Label>First 6-digit code</Label>
                              <p className="text-xs text-muted-foreground">Enter a code from your authenticator app.</p>
                            </div>
                            <div className="flex justify-center">
                              <OtpInput
                                value={totpCode}
                                onChange={setTotpCode}
                                disabled={mfaLoading}
                                autoFocus
                              />
                            </div>
                            <div>
                              <Label>Second 6-digit code</Label>
                              <p className="text-xs text-muted-foreground">Wait for a new code, then enter it to confirm the device.</p>
                            </div>
                            <div className="flex justify-center">
                              <OtpInput
                                value={totpCode2}
                                onChange={setTotpCode2}
                                onComplete={(val) => { void handleTotpConfirm(val); }}
                                disabled={mfaLoading}
                              />
                            </div>
                            <Button
                              type="button"
                              className="w-full"
                              onClick={() => { void handleTotpConfirm(totpCode2); }}
                              disabled={mfaLoading || totpCode.length !== 6 || totpCode2.length !== 6}
                            >
                              Verify authenticator
                            </Button>
                          </div>
                        )}
                        {totpVerified && (
                          <p className="text-xs text-muted-foreground">Authenticator verified.</p>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
              {recoveryCodes.length > 0 && (
                <div className="mx-6 mb-4 rounded-lg border border-amber-300 bg-amber-50 p-3">
                  <p className="mb-2 text-sm font-semibold text-amber-900">Save your recovery codes</p>
                  <p className="mb-2 text-xs text-amber-800">
                    Store these codes somewhere safe. Each can be used once to regain access if you lose your MFA device.
                  </p>
                  <div className="grid grid-cols-2 gap-1 font-mono text-xs">
                    {recoveryCodes.map((code) => (
                      <span key={code} className="rounded bg-amber-100 px-2 py-0.5 text-center text-amber-900">{code}</span>
                    ))}
                  </div>
                  <button
                    type="button"
                    className="mt-2 text-xs text-amber-700 underline hover:text-amber-900"
                    onClick={() => {
                      const text = `Recovery Codes\n\n${recoveryCodes.join("\n")}\n\nGenerated: ${new Date().toISOString()}`;
                      const blob = new Blob([text], { type: "text/plain" });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a");
                      a.href = url;
                      a.download = "recovery-codes.txt";
                      a.click();
                      URL.revokeObjectURL(url);
                    }}
                  >
                    Download as .txt
                  </button>
                </div>
              )}
              <CardFooter className="flex flex-col gap-3">
                <Button
                  type="button"
                  className="w-full"
                  size="lg"
                  disabled={(pendingSmsMfa && !smsVerified) || (pendingTotpMfa && !totpVerified)}
                  onClick={() => navigate("/", { replace: true })}
                >
                  Continue to app
                </Button>
              </CardFooter>
            </div>
          )}

          {step === "success" && (
            <div>
              <CardHeader className="space-y-2 text-center">
                <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-primary/10 text-primary">
                  <CheckCircle2 className="h-6 w-6" />
                </div>
                <CardTitle className="text-xl">Registration complete</CardTitle>
                <CardDescription>{message ?? "You're all set to sign in."}</CardDescription>
              </CardHeader>
              <CardFooter className="flex flex-col gap-4">
                <Button type="button" className="w-full" size="lg" onClick={() => navigate("/login")}>
                  Continue to sign in
                </Button>
              </CardFooter>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
