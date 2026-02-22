import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Smartphone,
  Mail,
  KeyRound,
  Plus,
  Trash2,
  CheckCircle2,
  XCircle,
  Loader2,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  getTotpDevices,
  beginTotpEnrollment,
  confirmTotpEnrollment,
  removeTotpDevice,
  getSmsDevices,
  beginSmsEnrollment,
  confirmSmsEnrollment,
  beginSmsRemoval,
  confirmSmsRemoval,
  getEmailDevices,
  beginEmailEnrollment,
  confirmEmailEnrollment,
  beginEmailRemoval,
  confirmEmailRemoval,
} from "@/api/endpoints/account";

// ─── TOTP Section ────────────────────────────────────────────────

function TotpSection() {
  const queryClient = useQueryClient();
  const [enrollOpen, setEnrollOpen] = useState(false);
  const [enrollStep, setEnrollStep] = useState<"qr" | "confirm" | "recovery">("qr");
  const [enrollData, setEnrollData] = useState<{ device_id: string; qr_code_uri: string; secret: string } | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [removeTarget, setRemoveTarget] = useState<string | null>(null);
  const [removeCode, setRemoveCode] = useState("");

  const devicesQuery = useQuery({
    queryKey: ["mfa", "totp", "devices"],
    queryFn: getTotpDevices,
  });

  const beginMutation = useMutation({
    mutationFn: () => beginTotpEnrollment({ label: "Authenticator App" }),
    onSuccess: (data) => {
      setEnrollData(data);
      setEnrollStep("qr");
      setEnrollOpen(true);
    },
    onError: () => toast.error("Failed to start TOTP enrollment"),
  });

  const confirmMutation = useMutation({
    mutationFn: () => confirmTotpEnrollment({ device_id: enrollData?.device_id ?? "", totp_code: totpCode }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["mfa", "totp", "devices"] });
      setTotpCode("");
      if (data.recovery_codes.length > 0) {
        setRecoveryCodes(data.recovery_codes);
        setEnrollStep("recovery");
      } else {
        toast.success("Authenticator added");
        setEnrollOpen(false);
        setEnrollData(null);
      }
    },
    onError: () => toast.error("Invalid code, please try again"),
  });

  const removeMutation = useMutation({
    mutationFn: () => removeTotpDevice(removeTarget ?? "", removeCode),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mfa", "totp", "devices"] });
      toast.success("Device removed");
      setRemoveTarget(null);
      setRemoveCode("");
    },
    onError: () => toast.error("Failed to remove device"),
  });

  const devices = devicesQuery.data?.devices ?? [];

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-muted-foreground" />
            <CardTitle className="text-base">Authenticator Apps (TOTP)</CardTitle>
          </div>
          <Button
            size="sm"
            variant="outline"
            onClick={() => beginMutation.mutate()}
            disabled={beginMutation.isPending}
          >
            <Plus className="mr-1 h-3.5 w-3.5" />
            Add
          </Button>
        </div>
        <CardDescription>Time-based one-time password authenticator apps</CardDescription>
      </CardHeader>
      <CardContent>
        {devicesQuery.isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-12 w-full" />
          </div>
        ) : devices.length === 0 ? (
          <p className="text-sm text-muted-foreground">No authenticator apps configured.</p>
        ) : (
          <ul className="divide-y">
            {devices.map((d) => (
              <li key={d.device_id} className="flex items-center justify-between py-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium">{d.label ?? "Authenticator"}</p>
                  <p className="text-xs text-muted-foreground">
                    Added {new Date(d.created_at * 1000).toLocaleDateString()}
                    {d.last_used_at ? ` · Last used ${new Date(d.last_used_at * 1000).toLocaleDateString()}` : ""}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant={d.enabled ? "default" : "secondary"}>
                    {d.enabled ? <><CheckCircle2 className="mr-1 h-3 w-3" />Enabled</> : <><XCircle className="mr-1 h-3 w-3" />Disabled</>}
                  </Badge>
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() => setRemoveTarget(d.device_id)}
                    aria-label="Remove device"
                  >
                    <Trash2 className="h-4 w-4 text-destructive" />
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>

      {/* Enrollment dialog */}
      <Dialog open={enrollOpen} onOpenChange={(o) => {
        if (!o) {
          setEnrollOpen(false);
          setTotpCode("");
          setEnrollData(null);
          setRecoveryCodes([]);
          setEnrollStep("qr");
        }
      }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Authenticator App</DialogTitle>
            <DialogDescription>
              {enrollStep === "qr"
                ? "Scan the QR code with your authenticator app, then enter the 6-digit code."
                : enrollStep === "confirm"
                  ? "Enter the 6-digit code from your authenticator app to confirm."
                  : "Save these recovery codes somewhere safe. They can be used to access your account if you lose your authenticator."}
            </DialogDescription>
          </DialogHeader>
          {enrollStep === "recovery" ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-2 rounded-lg border bg-muted p-3">
                {recoveryCodes.map((code) => (
                  <code key={code} className="text-center text-sm font-mono">{code}</code>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">
                These codes will not be shown again. Store them in a password manager or other secure location.
              </p>
              <DialogFooter>
                <Button className="w-full" onClick={() => {
                  toast.success("Authenticator added");
                  setEnrollOpen(false);
                  setEnrollData(null);
                  setRecoveryCodes([]);
                  setEnrollStep("qr");
                }}>
                  I&apos;ve saved my recovery codes
                </Button>
              </DialogFooter>
            </div>
          ) : enrollData && (
            <div className="space-y-4">
              {enrollStep === "qr" && (
                <div className="space-y-3">
                  <div className="flex justify-center rounded-lg border bg-white p-4">
                    <img src={enrollData.qr_code_uri} alt="TOTP QR Code" className="h-48 w-48" />
                  </div>
                  <div>
                    <Label className="text-xs text-muted-foreground">Manual entry key</Label>
                    <code className="mt-1 block break-all rounded bg-muted px-2 py-1 text-xs font-mono">
                      {enrollData.secret}
                    </code>
                  </div>
                  <Button className="w-full" onClick={() => setEnrollStep("confirm")}>
                    I&apos;ve scanned the code
                  </Button>
                </div>
              )}
              {enrollStep === "confirm" && (
                <form
                  onSubmit={(e) => { e.preventDefault(); confirmMutation.mutate(); }}
                  className="space-y-3"
                >
                  <div>
                    <Label htmlFor="totp-code">6-digit code</Label>
                    <Input
                      id="totp-code"
                      value={totpCode}
                      onChange={(e) => setTotpCode(e.target.value)}
                      placeholder="000000"
                      maxLength={6}
                      pattern="\d{6}"
                      autoFocus
                    />
                  </div>
                  <DialogFooter>
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => setEnrollStep("qr")}
                    >
                      Back
                    </Button>
                    <Button type="submit" disabled={totpCode.length !== 6 || confirmMutation.isPending}>
                      {confirmMutation.isPending ? <><Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />Verifying...</> : "Verify"}
                    </Button>
                  </DialogFooter>
                </form>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Remove dialog - requires re-auth with TOTP code */}
      <Dialog open={!!removeTarget} onOpenChange={(o) => { if (!o) { setRemoveTarget(null); setRemoveCode(""); } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Remove TOTP Device</DialogTitle>
            <DialogDescription>
              Enter a valid TOTP code from another device to confirm removal.
            </DialogDescription>
          </DialogHeader>
          <form
            onSubmit={(e) => { e.preventDefault(); removeMutation.mutate(); }}
            className="space-y-3"
          >
            <div>
              <Label htmlFor="remove-totp">TOTP code</Label>
              <Input
                id="remove-totp"
                value={removeCode}
                onChange={(e) => setRemoveCode(e.target.value)}
                placeholder="000000"
                maxLength={6}
                autoFocus
              />
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setRemoveTarget(null)}>Cancel</Button>
              <Button type="submit" variant="destructive" disabled={removeCode.length !== 6 || removeMutation.isPending}>
                {removeMutation.isPending ? "Removing..." : "Remove"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </Card>
  );
}

// ─── SMS Section ─────────────────────────────────────────────────

function SmsSection() {
  const queryClient = useQueryClient();
  const [enrollOpen, setEnrollOpen] = useState(false);
  const [phone, setPhone] = useState("");
  const [challengeId, setChallengeId] = useState<string | null>(null);
  const [verifyCode, setVerifyCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [removeTarget, setRemoveTarget] = useState<string | null>(null);
  const [removeChallengeId, setRemoveChallengeId] = useState<string | null>(null);
  const [removeCode, setRemoveCode] = useState("");

  const devicesQuery = useQuery({
    queryKey: ["mfa", "sms", "devices"],
    queryFn: getSmsDevices,
  });

  const beginMutation = useMutation({
    mutationFn: () => beginSmsEnrollment({ phone_e164: phone }),
    onSuccess: (data) => {
      setChallengeId(data.challenge_id);
    },
    onError: () => toast.error("Failed to send SMS verification"),
  });

  const confirmMutation = useMutation({
    mutationFn: () => confirmSmsEnrollment({ challenge_id: challengeId ?? "", code: verifyCode }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["mfa", "sms", "devices"] });
      setVerifyCode("");
      if (data.recovery_codes.length > 0) {
        setRecoveryCodes(data.recovery_codes);
      } else {
        toast.success("SMS device added");
        setEnrollOpen(false);
        setPhone("");
        setChallengeId(null);
      }
    },
    onError: () => toast.error("Invalid code"),
  });

  const beginRemoveMutation = useMutation({
    mutationFn: (smsDeviceId: string) => beginSmsRemoval(smsDeviceId),
    onSuccess: (data) => {
      setRemoveChallengeId(data.challenge_id);
    },
    onError: () => toast.error("Failed to begin removal"),
  });

  const confirmRemoveMutation = useMutation({
    mutationFn: () => confirmSmsRemoval({ challenge_id: removeChallengeId ?? "", code: removeCode }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mfa", "sms", "devices"] });
      toast.success("SMS device removed");
      setRemoveTarget(null);
      setRemoveChallengeId(null);
      setRemoveCode("");
    },
    onError: () => toast.error("Failed to remove device"),
  });

  const devices = devicesQuery.data?.devices ?? [];

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Smartphone className="h-5 w-5 text-muted-foreground" />
            <CardTitle className="text-base">SMS Devices</CardTitle>
          </div>
          <Button
            size="sm"
            variant="outline"
            onClick={() => { setEnrollOpen(true); setChallengeId(null); setPhone(""); setVerifyCode(""); }}
          >
            <Plus className="mr-1 h-3.5 w-3.5" />
            Add
          </Button>
        </div>
        <CardDescription>Phone numbers for SMS verification codes</CardDescription>
      </CardHeader>
      <CardContent>
        {devicesQuery.isLoading ? (
          <Skeleton className="h-12 w-full" />
        ) : devices.length === 0 ? (
          <p className="text-sm text-muted-foreground">No SMS devices configured.</p>
        ) : (
          <ul className="divide-y">
            {devices.map((d) => (
              <li key={d.sms_device_id} className="flex items-center justify-between py-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium">{d.label || d.phone_e164}</p>
                  <p className="text-xs text-muted-foreground">
                    Added {new Date(d.created_at * 1000).toLocaleDateString()}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant={d.enabled ? "default" : "secondary"}>
                    {d.enabled ? "Enabled" : d.pending ? "Pending" : "Disabled"}
                  </Badge>
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() => {
                      setRemoveTarget(d.sms_device_id);
                      beginRemoveMutation.mutate(d.sms_device_id);
                    }}
                    aria-label="Remove SMS device"
                  >
                    <Trash2 className="h-4 w-4 text-destructive" />
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>

      {/* Enrollment dialog */}
      <Dialog open={enrollOpen} onOpenChange={(o) => {
        if (!o) {
          setEnrollOpen(false);
          setPhone("");
          setChallengeId(null);
          setVerifyCode("");
          setRecoveryCodes([]);
        }
      }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add SMS Device</DialogTitle>
            <DialogDescription>
              {recoveryCodes.length > 0
                ? "Save these recovery codes somewhere safe. They can be used to access your account if you lose access to your phone."
                : challengeId
                  ? "Enter the verification code sent to your phone."
                  : "Enter the phone number in E.164 format (e.g. +12125551234)."}
            </DialogDescription>
          </DialogHeader>
          {recoveryCodes.length > 0 ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-2 rounded-lg border bg-muted p-3">
                {recoveryCodes.map((code) => (
                  <code key={code} className="text-center text-sm font-mono">{code}</code>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">
                These codes will not be shown again. Store them in a password manager or other secure location.
              </p>
              <DialogFooter>
                <Button className="w-full" onClick={() => {
                  toast.success("SMS device added");
                  setEnrollOpen(false);
                  setPhone("");
                  setChallengeId(null);
                  setRecoveryCodes([]);
                }}>
                  I&apos;ve saved my recovery codes
                </Button>
              </DialogFooter>
            </div>
          ) : !challengeId ? (
            <form onSubmit={(e) => { e.preventDefault(); beginMutation.mutate(); }} className="space-y-3">
              <div>
                <Label htmlFor="sms-phone">Phone number</Label>
                <Input id="sms-phone" value={phone} onChange={(e) => setPhone(e.target.value)} placeholder="+12125551234" autoFocus />
              </div>
              <DialogFooter>
                <Button type="submit" disabled={!phone.trim() || beginMutation.isPending}>
                  {beginMutation.isPending ? "Sending..." : "Send Code"}
                </Button>
              </DialogFooter>
            </form>
          ) : (
            <form onSubmit={(e) => { e.preventDefault(); confirmMutation.mutate(); }} className="space-y-3">
              <div>
                <Label htmlFor="sms-code">Verification code</Label>
                <Input id="sms-code" value={verifyCode} onChange={(e) => setVerifyCode(e.target.value)} placeholder="123456" maxLength={6} autoFocus />
              </div>
              <DialogFooter>
                <Button type="submit" disabled={!verifyCode.trim() || confirmMutation.isPending}>
                  {confirmMutation.isPending ? "Verifying..." : "Verify"}
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>

      {/* Removal confirmation dialog */}
      <Dialog open={!!removeTarget} onOpenChange={(o) => { if (!o) { setRemoveTarget(null); setRemoveChallengeId(null); setRemoveCode(""); } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Remove SMS Device</DialogTitle>
            <DialogDescription>Enter the verification code sent to your phone to confirm removal.</DialogDescription>
          </DialogHeader>
          {removeChallengeId ? (
            <form onSubmit={(e) => { e.preventDefault(); confirmRemoveMutation.mutate(); }} className="space-y-3">
              <div>
                <Label htmlFor="sms-remove-code">Verification code</Label>
                <Input id="sms-remove-code" value={removeCode} onChange={(e) => setRemoveCode(e.target.value)} placeholder="123456" maxLength={6} autoFocus />
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setRemoveTarget(null)}>Cancel</Button>
                <Button type="submit" variant="destructive" disabled={!removeCode.trim() || confirmRemoveMutation.isPending}>
                  {confirmRemoveMutation.isPending ? "Removing..." : "Remove"}
                </Button>
              </DialogFooter>
            </form>
          ) : (
            <div className="flex justify-center py-4">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          )}
        </DialogContent>
      </Dialog>
    </Card>
  );
}

// ─── Email Section ───────────────────────────────────────────────

function EmailSection() {
  const queryClient = useQueryClient();
  const [enrollOpen, setEnrollOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [challengeId, setChallengeId] = useState<string | null>(null);
  const [verifyCode, setVerifyCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [removeTarget, setRemoveTarget] = useState<string | null>(null);
  const [removeChallengeId, setRemoveChallengeId] = useState<string | null>(null);
  const [removeCode, setRemoveCode] = useState("");

  const devicesQuery = useQuery({
    queryKey: ["mfa", "email", "devices"],
    queryFn: getEmailDevices,
  });

  const beginMutation = useMutation({
    mutationFn: () => beginEmailEnrollment({ email }),
    onSuccess: (data) => {
      setChallengeId(data.challenge_id);
    },
    onError: () => toast.error("Failed to send email verification"),
  });

  const confirmMutation = useMutation({
    mutationFn: () => confirmEmailEnrollment({ challenge_id: challengeId ?? "", code: verifyCode }),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["mfa", "email", "devices"] });
      setVerifyCode("");
      if (data.recovery_codes.length > 0) {
        setRecoveryCodes(data.recovery_codes);
      } else {
        toast.success("Email device added");
        setEnrollOpen(false);
        setEmail("");
        setChallengeId(null);
      }
    },
    onError: () => toast.error("Invalid code"),
  });

  const beginRemoveMutation = useMutation({
    mutationFn: (emailDeviceId: string) => beginEmailRemoval(emailDeviceId),
    onSuccess: (data) => {
      setRemoveChallengeId(data.challenge_id);
    },
    onError: () => toast.error("Failed to begin removal"),
  });

  const confirmRemoveMutation = useMutation({
    mutationFn: () => confirmEmailRemoval({ challenge_id: removeChallengeId ?? "", code: removeCode }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mfa", "email", "devices"] });
      toast.success("Email device removed");
      setRemoveTarget(null);
      setRemoveChallengeId(null);
      setRemoveCode("");
    },
    onError: () => toast.error("Failed to remove device"),
  });

  const devices = devicesQuery.data?.devices ?? [];

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Mail className="h-5 w-5 text-muted-foreground" />
            <CardTitle className="text-base">Email Devices</CardTitle>
          </div>
          <Button
            size="sm"
            variant="outline"
            onClick={() => { setEnrollOpen(true); setChallengeId(null); setEmail(""); setVerifyCode(""); }}
          >
            <Plus className="mr-1 h-3.5 w-3.5" />
            Add
          </Button>
        </div>
        <CardDescription>Email addresses for verification codes</CardDescription>
      </CardHeader>
      <CardContent>
        {devicesQuery.isLoading ? (
          <Skeleton className="h-12 w-full" />
        ) : devices.length === 0 ? (
          <p className="text-sm text-muted-foreground">No email devices configured.</p>
        ) : (
          <ul className="divide-y">
            {devices.map((d) => (
              <li key={d.email_device_id} className="flex items-center justify-between py-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium">{d.label ?? d.email}</p>
                  <p className="text-xs text-muted-foreground">
                    Added {new Date(d.created_at * 1000).toLocaleDateString()}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant={d.enabled ? "default" : "secondary"}>
                    {d.enabled ? "Enabled" : d.pending ? "Pending" : "Disabled"}
                  </Badge>
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() => {
                      setRemoveTarget(d.email_device_id);
                      beginRemoveMutation.mutate(d.email_device_id);
                    }}
                    aria-label="Remove email device"
                  >
                    <Trash2 className="h-4 w-4 text-destructive" />
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>

      {/* Enrollment dialog */}
      <Dialog open={enrollOpen} onOpenChange={(o) => {
        if (!o) {
          setEnrollOpen(false);
          setEmail("");
          setChallengeId(null);
          setVerifyCode("");
          setRecoveryCodes([]);
        }
      }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Email Device</DialogTitle>
            <DialogDescription>
              {recoveryCodes.length > 0
                ? "Save these recovery codes somewhere safe. They can be used to access your account if you lose access to your email."
                : challengeId
                  ? "Enter the verification code sent to your email."
                  : "Enter the email address for verification."}
            </DialogDescription>
          </DialogHeader>
          {recoveryCodes.length > 0 ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-2 rounded-lg border bg-muted p-3">
                {recoveryCodes.map((code) => (
                  <code key={code} className="text-center text-sm font-mono">{code}</code>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">
                These codes will not be shown again. Store them in a password manager or other secure location.
              </p>
              <DialogFooter>
                <Button className="w-full" onClick={() => {
                  toast.success("Email device added");
                  setEnrollOpen(false);
                  setEmail("");
                  setChallengeId(null);
                  setRecoveryCodes([]);
                }}>
                  I&apos;ve saved my recovery codes
                </Button>
              </DialogFooter>
            </div>
          ) : !challengeId ? (
            <form onSubmit={(e) => { e.preventDefault(); beginMutation.mutate(); }} className="space-y-3">
              <div>
                <Label htmlFor="email-addr">Email address</Label>
                <Input id="email-addr" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" autoFocus />
              </div>
              <DialogFooter>
                <Button type="submit" disabled={!email.trim() || beginMutation.isPending}>
                  {beginMutation.isPending ? "Sending..." : "Send Code"}
                </Button>
              </DialogFooter>
            </form>
          ) : (
            <form onSubmit={(e) => { e.preventDefault(); confirmMutation.mutate(); }} className="space-y-3">
              <div>
                <Label htmlFor="email-code">Verification code</Label>
                <Input id="email-code" value={verifyCode} onChange={(e) => setVerifyCode(e.target.value)} placeholder="123456" maxLength={6} autoFocus />
              </div>
              <DialogFooter>
                <Button type="submit" disabled={!verifyCode.trim() || confirmMutation.isPending}>
                  {confirmMutation.isPending ? "Verifying..." : "Verify"}
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>

      {/* Removal confirmation dialog */}
      <Dialog open={!!removeTarget} onOpenChange={(o) => { if (!o) { setRemoveTarget(null); setRemoveChallengeId(null); setRemoveCode(""); } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Remove Email Device</DialogTitle>
            <DialogDescription>Enter the verification code sent to your email to confirm removal.</DialogDescription>
          </DialogHeader>
          {removeChallengeId ? (
            <form onSubmit={(e) => { e.preventDefault(); confirmRemoveMutation.mutate(); }} className="space-y-3">
              <div>
                <Label htmlFor="email-remove-code">Verification code</Label>
                <Input id="email-remove-code" value={removeCode} onChange={(e) => setRemoveCode(e.target.value)} placeholder="123456" maxLength={6} autoFocus />
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setRemoveTarget(null)}>Cancel</Button>
                <Button type="submit" variant="destructive" disabled={!removeCode.trim() || confirmRemoveMutation.isPending}>
                  {confirmRemoveMutation.isPending ? "Removing..." : "Remove"}
                </Button>
              </DialogFooter>
            </form>
          ) : (
            <div className="flex justify-center py-4">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          )}
        </DialogContent>
      </Dialog>
    </Card>
  );
}

// ─── Main Export ──────────────────────────────────────────────────

export function MfaDevices() {
  return (
    <div className="space-y-6">
      <TotpSection />
      <SmsSection />
      <EmailSection />
    </div>
  );
}
