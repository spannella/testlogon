import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { ShieldAlert, KeyRound, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { passwordRecoveryStart, passwordRecoveryConfirm } from "@/api/endpoints/auth";
import { OtpInput } from "@/components/ui/otp-input";

export function Recovery() {
  return (
    <div className="space-y-6">
      <PasswordRecoverySection />
    </div>
  );
}

function PasswordRecoverySection() {
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState<"start" | "confirm">("start");
  const [username, setUsername] = useState("");
  const [deliveryInfo, setDeliveryInfo] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const startMutation = useMutation({
    mutationFn: () => passwordRecoveryStart({ username }),
    onSuccess: (data) => {
      const dest = data.delivery_destination
        ? `Code sent to ${data.delivery_destination}`
        : "Verification code sent";
      setDeliveryInfo(dest);
      setStep("confirm");
    },
    onError: () => toast.error("Failed to initiate password recovery"),
  });

  const confirmMutation = useMutation({
    mutationFn: () =>
      passwordRecoveryConfirm({
        username,
        confirmation_code: code,
        new_password: newPassword,
      }),
    onSuccess: () => {
      toast.success("Password changed successfully");
      handleClose();
    },
    onError: () => toast.error("Failed to change password. Check your code and try again."),
  });

  const handleClose = () => {
    setOpen(false);
    setStep("start");
    setUsername("");
    setDeliveryInfo(null);
    setCode("");
    setNewPassword("");
    setConfirmPassword("");
  };

  const passwordsMatch = newPassword === confirmPassword;
  const passwordValid = newPassword.length >= 8;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-muted-foreground" />
            <CardTitle className="text-base">Password Recovery</CardTitle>
          </div>
          <Button size="sm" variant="outline" onClick={() => setOpen(true)}>
            <ShieldAlert className="mr-1 h-3.5 w-3.5" />
            Reset Password
          </Button>
        </div>
        <CardDescription>
          Reset your password using a verification code sent to your registered email or phone.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground">
          If you&apos;ve forgotten your password or want to change it, use the password recovery flow.
          A verification code will be sent to your registered contact method.
        </p>
      </CardContent>

      <Dialog open={open} onOpenChange={(o) => { if (!o) handleClose(); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Password Recovery</DialogTitle>
            <DialogDescription>
              {step === "start"
                ? "Enter your username to receive a verification code."
                : deliveryInfo ?? "Enter the code and your new password."}
            </DialogDescription>
          </DialogHeader>

          {step === "start" ? (
            <form onSubmit={(e) => { e.preventDefault(); startMutation.mutate(); }} className="space-y-3">
              <div>
                <Label htmlFor="recovery-username">Username</Label>
                <Input
                  id="recovery-username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="your-username"
                  autoFocus
                />
              </div>
              <DialogFooter>
                <Button type="submit" disabled={!username.trim() || startMutation.isPending}>
                  {startMutation.isPending ? (
                    <><Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />Sending...</>
                  ) : (
                    "Send Code"
                  )}
                </Button>
              </DialogFooter>
            </form>
          ) : (
            <form onSubmit={(e) => { e.preventDefault(); confirmMutation.mutate(); }} className="space-y-3">
              <div className="space-y-2">
                <Label>Verification code</Label>
                <div className="flex justify-center">
                  <OtpInput
                    value={code}
                    onChange={setCode}
                    disabled={confirmMutation.isPending}
                    autoFocus
                  />
                </div>
              </div>
              <div>
                <Label htmlFor="new-pw">New password</Label>
                <Input
                  id="new-pw"
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="At least 8 characters"
                />
              </div>
              <div>
                <Label htmlFor="confirm-pw">Confirm password</Label>
                <Input
                  id="confirm-pw"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Repeat new password"
                />
                {confirmPassword && !passwordsMatch && (
                  <p className="mt-1 text-xs text-destructive">Passwords do not match</p>
                )}
              </div>
              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setStep("start")}
                >
                  Back
                </Button>
                <Button
                  type="submit"
                  disabled={
                    !code.trim() || !passwordValid || !passwordsMatch || confirmMutation.isPending
                  }
                >
                  {confirmMutation.isPending ? (
                    <><Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />Changing...</>
                  ) : (
                    "Change Password"
                  )}
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>
    </Card>
  );
}
