import { useState } from "react";
import { Fingerprint, Plus, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState } from "@/components/shared/EmptyState";
import { registerBegin, registerFinish } from "@/api/endpoints/webauthn";

interface StoredKey {
  credential_id: string;
  label: string;
  registered_at: string;
}

export function WebAuthnDevices() {
  const [keys, setKeys] = useState<StoredKey[]>([]);
  const [registering, setRegistering] = useState(false);
  const [labelDialogOpen, setLabelDialogOpen] = useState(false);
  const [pendingCredential, setPendingCredential] = useState<Record<string, unknown> | null>(null);
  const [keyLabel, setKeyLabel] = useState("");
  const [saving, setSaving] = useState(false);

  const handleRegister = async () => {
    setRegistering(true);
    try {
      const beginResp = await registerBegin({});
      const options = beginResp.options;

      // Call WebAuthn browser API
      const credential = await navigator.credentials.create({
        publicKey: options as unknown as PublicKeyCredentialCreationOptions,
      });

      if (!credential) {
        toast.error("Registration cancelled");
        return;
      }

      // Store credential and open label dialog
      const pkCred = credential as PublicKeyCredential;
      const response = pkCred.response as AuthenticatorAttestationResponse;

      setPendingCredential({
        id: pkCred.id,
        rawId: btoa(String.fromCharCode(...new Uint8Array(pkCred.rawId))),
        type: pkCred.type,
        response: {
          attestationObject: btoa(
            String.fromCharCode(...new Uint8Array(response.attestationObject)),
          ),
          clientDataJSON: btoa(
            String.fromCharCode(...new Uint8Array(response.clientDataJSON)),
          ),
        },
      });
      setKeyLabel("");
      setLabelDialogOpen(true);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Registration failed";
      toast.error(msg);
    } finally {
      setRegistering(false);
    }
  };

  const handleFinish = async () => {
    if (!pendingCredential) return;
    setSaving(true);
    try {
      const resp = await registerFinish({
        credential: pendingCredential,
        label: keyLabel.trim() || undefined,
      });

      setKeys((prev) => [
        ...prev,
        {
          credential_id: resp.credential_id,
          label: keyLabel.trim() || "Security Key",
          registered_at: new Date().toISOString(),
        },
      ]);

      setLabelDialogOpen(false);
      setPendingCredential(null);
      toast.success("Security key registered");
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to save key";
      toast.error(msg);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {keys.length} security key{keys.length !== 1 ? "s" : ""} registered
        </p>
        <Button
          variant="outline"
          size="sm"
          onClick={handleRegister}
          disabled={registering}
        >
          {registering ? (
            <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
          ) : (
            <Plus className="mr-1 h-3.5 w-3.5" />
          )}
          Add Security Key
        </Button>
      </div>

      {keys.length === 0 ? (
        <EmptyState
          icon={<Fingerprint className="h-6 w-6" />}
          title="No security keys"
          description="Register a FIDO2 security key for passwordless authentication"
          className="py-12"
        />
      ) : (
        <div className="divide-y rounded-lg border">
          {keys.map((key) => (
            <div
              key={key.credential_id}
              className="flex items-center justify-between px-4 py-3"
            >
              <div className="flex items-center gap-3">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-muted">
                  <Fingerprint className="h-4 w-4" />
                </div>
                <div>
                  <p className="text-sm font-medium">{key.label}</p>
                  <p className="text-xs text-muted-foreground">
                    Registered {new Date(key.registered_at).toLocaleDateString()}
                  </p>
                </div>
              </div>
              <p className="font-mono text-xs text-muted-foreground">
                {key.credential_id.slice(0, 12)}...
              </p>
            </div>
          ))}
        </div>
      )}

      {/* Label dialog */}
      <Dialog open={labelDialogOpen} onOpenChange={setLabelDialogOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Name your security key</DialogTitle>
          </DialogHeader>
          <div className="space-y-2 py-2">
            <Label htmlFor="key-label">Label (optional)</Label>
            <Input
              id="key-label"
              placeholder="e.g. YubiKey 5"
              value={keyLabel}
              onChange={(e) => setKeyLabel(e.target.value)}
              autoFocus
              onKeyDown={(e) => {
                if (e.key === "Enter") handleFinish();
              }}
            />
          </div>
          <DialogFooter>
            <Button onClick={handleFinish} disabled={saving}>
              {saving ? (
                <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
              ) : null}
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
