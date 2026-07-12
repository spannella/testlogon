import * as React from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowLeft, Copy, Link2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SignaturePacketComposer } from "@/pages/files/SignaturePacketComposer";
import { createSignerSigningLink } from "@/api/endpoints/signaturePackets";

/**
 * CreateSignatureRequestPage (SUX-009) — first-class standalone request creator.
 *
 * Wraps the existing SignaturePacketComposer (pick source PDF → add signers →
 * place fields → send) and adds a post-send "Create signing link per signer"
 * affordance (SUX-005) with copy-to-clipboard.
 */
export default function CreateSignatureRequestPage() {
  const [searchParams] = useSearchParams();
  const resumePacketId = searchParams.get("packet") ?? undefined;
  const [linkPacketId, setLinkPacketId] = React.useState("");
  const [linkSignerId, setLinkSignerId] = React.useState("");
  const [generatedUrl, setGeneratedUrl] = React.useState("");
  const [generatedExpiry, setGeneratedExpiry] = React.useState<number | null>(null);
  const [busy, setBusy] = React.useState(false);

  const generateLink = React.useCallback(async () => {
    const pid = linkPacketId.trim();
    const sid = linkSignerId.trim();
    if (!pid || !sid) {
      toast.error("Packet ID and signer ID are required");
      return;
    }
    setBusy(true);
    try {
      const res = await createSignerSigningLink(pid, sid);
      setGeneratedUrl(res.url);
      setGeneratedExpiry(res.expires_at);
      toast.success("Signing link created");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      toast.error(message);
    } finally {
      setBusy(false);
    }
  }, [linkPacketId, linkSignerId]);

  const copyLink = React.useCallback(async () => {
    if (!generatedUrl) return;
    try {
      await navigator.clipboard.writeText(generatedUrl);
      toast.success("Copied to clipboard");
    } catch {
      toast.error("Could not copy — select and copy the link manually");
    }
  }, [generatedUrl]);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Button asChild variant="ghost" size="sm">
            <Link to="/signing">
              <ArrowLeft className="mr-1 h-4 w-4" /> Signing hub
            </Link>
          </Button>
          <h1 className="text-xl font-semibold">New signature request</h1>
        </div>
      </div>

      <p className="text-sm text-muted-foreground">
        Pick a source PDF, add signer fields, then send. After sending you can mint a per-signer public link below.
      </p>

      <SignaturePacketComposer initialPacketId={resumePacketId} />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Link2 className="h-5 w-5" /> Create signing link per signer
          </CardTitle>
          <CardDescription>
            Generate a secure, single-use public link for a signer (works after the packet is sent).
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-3 md:grid-cols-[1fr_1fr_auto]">
            <div className="space-y-1">
              <Label htmlFor="link-packet-id">Packet ID</Label>
              <Input
                id="link-packet-id"
                placeholder="Packet ID (from above)"
                value={linkPacketId}
                onChange={(e) => setLinkPacketId(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="link-signer-id">Signer ID</Label>
              <Input
                id="link-signer-id"
                placeholder="Signer ID"
                value={linkSignerId}
                onChange={(e) => setLinkSignerId(e.target.value)}
              />
            </div>
            <div className="flex items-end">
              <Button onClick={() => void generateLink()} disabled={busy}>
                Create link
              </Button>
            </div>
          </div>

          {generatedUrl && (
            <div className="space-y-2 rounded-md border bg-muted/20 p-3" data-testid="generated-signing-link">
              <div className="flex items-center gap-2">
                <Input readOnly value={generatedUrl} className="font-mono text-xs" />
                <Button size="sm" variant="outline" onClick={() => void copyLink()}>
                  <Copy className="mr-1 h-4 w-4" /> Copy
                </Button>
              </div>
              {generatedExpiry ? (
                <div className="text-xs text-muted-foreground">
                  Expires: {new Date(generatedExpiry * 1000).toLocaleString()}
                </div>
              ) : null}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
