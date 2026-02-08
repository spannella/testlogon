import { useEffect, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { Loader2, CheckCircle2, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAuthStore } from "@/stores/authStore";
import { passwordlessVerify } from "@/api/endpoints/auth";

export default function MagicLinkVerify() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { login } = useAuthStore();

  const [status, setStatus] = useState<"loading" | "success" | "error" | "mfa">("loading");
  const [errorMsg, setErrorMsg] = useState("");

  const token = searchParams.get("token") ?? "";

  useEffect(() => {
    if (!token) {
      setStatus("error");
      setErrorMsg("No verification token found in the URL.");
      return;
    }

    let cancelled = false;

    const verify = async () => {
      try {
        const resp = await passwordlessVerify({ token });

        if (cancelled) return;

        if (resp.status === "ok" && resp.session_id) {
          setStatus("success");
          login(resp.session_id, "");
          // Brief delay to show success state before redirect
          setTimeout(() => {
            if (!cancelled) navigate("/", { replace: true });
          }, 1200);
        } else if (resp.auth_required && resp.challenge_id) {
          // Additional MFA needed — redirect to login with challenge
          setStatus("mfa");
          setTimeout(() => {
            if (!cancelled) navigate("/login", { replace: true });
          }, 2000);
        } else {
          setStatus("error");
          setErrorMsg("Verification failed. The link may have expired.");
        }
      } catch {
        if (!cancelled) {
          setStatus("error");
          setErrorMsg("Verification failed. The link may have expired or already been used.");
        }
      }
    };

    verify();

    return () => {
      cancelled = true;
    };
  }, [token, login, navigate]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-background via-background to-primary/5 p-4">
      <div className="w-full max-w-sm text-center">
        {status === "loading" && (
          <div className="space-y-4">
            <Loader2 className="mx-auto h-12 w-12 animate-spin text-primary" />
            <h1 className="text-xl font-semibold">Verifying your link...</h1>
            <p className="text-sm text-muted-foreground">
              Please wait while we sign you in.
            </p>
          </div>
        )}

        {status === "success" && (
          <div className="space-y-4">
            <CheckCircle2 className="mx-auto h-12 w-12 text-emerald-500" />
            <h1 className="text-xl font-semibold">You&apos;re signed in!</h1>
            <p className="text-sm text-muted-foreground">
              Redirecting to your dashboard...
            </p>
          </div>
        )}

        {status === "mfa" && (
          <div className="space-y-4">
            <Loader2 className="mx-auto h-12 w-12 animate-spin text-primary" />
            <h1 className="text-xl font-semibold">Additional verification required</h1>
            <p className="text-sm text-muted-foreground">
              Redirecting to complete sign-in...
            </p>
          </div>
        )}

        {status === "error" && (
          <div className="space-y-4">
            <XCircle className="mx-auto h-12 w-12 text-destructive" />
            <h1 className="text-xl font-semibold">Verification failed</h1>
            <p className="text-sm text-muted-foreground">{errorMsg}</p>
            <Button
              variant="outline"
              onClick={() => navigate("/login", { replace: true })}
            >
              Back to login
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
