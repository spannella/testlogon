import * as React from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { FilePen } from "lucide-react";
import { SigningWidget } from "@/pages/signing/SigningWidget";
import type { SignaturePacketDetail } from "@/api/endpoints/signaturePackets";

/**
 * PublicSigningPage (SUX-006) — login-free signing at /sign/:token.
 *
 * Renders OUTSIDE the auth shell. Drives the reusable <SigningWidget> with the
 * public token. `?embed=1` produces a chromeless layout suitable for an
 * <iframe>; on completion it posts a `signing:completed` message to the host.
 */
export default function PublicSigningPage() {
  const { token } = useParams<{ token: string }>();
  const [searchParams] = useSearchParams();
  const embed = searchParams.get("embed") === "1";

  const handleCompleted = React.useCallback(
    (packet: SignaturePacketDetail) => {
      // Notify an embedding host page (iframe). Best-effort; no-op outside iframe.
      try {
        window.parent?.postMessage(
          { type: "signing:completed", packet_id: packet?.packet_id ?? null },
          "*",
        );
      } catch {
        /* ignore cross-origin/postMessage failures */
      }
    },
    [],
  );

  if (!token) {
    return (
      <div className="flex min-h-screen items-center justify-center p-6 text-sm text-muted-foreground">
        Missing signing token.
      </div>
    );
  }

  const widget = (
    <SigningWidget token={token} onCompleted={handleCompleted} compact={embed} />
  );

  if (embed) {
    // Chromeless: just the widget, sized to fit an iframe.
    return (
      <div className="min-h-screen w-full bg-background p-3" data-testid="public-signing-embed">
        {widget}
      </div>
    );
  }

  return (
    <div className="min-h-screen w-full bg-muted/30" data-testid="public-signing-page">
      <header className="border-b bg-background">
        <div className="mx-auto flex max-w-5xl items-center gap-2 px-4 py-4">
          <FilePen className="h-5 w-5 text-primary" />
          <div>
            <div className="text-base font-semibold">Sign document</div>
            <p className="text-xs text-muted-foreground">
              Review the document, fill your fields, and complete signing.
            </p>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-4 py-6">
        <div className="rounded-lg border bg-background p-4 shadow-sm">{widget}</div>
        <p className="mt-4 text-center text-xs text-muted-foreground">
          This is a secure, single-use signing link. Do not share it.
        </p>
      </main>
    </div>
  );
}
