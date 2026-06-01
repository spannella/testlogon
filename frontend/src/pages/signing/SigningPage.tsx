import { SignaturePacketComposer } from "@/pages/files/SignaturePacketComposer";
import { SignatureTemplateManager } from "@/pages/signing/SignatureTemplateManager";

export default function SigningPage() {
  return (
    <div className="p-6 space-y-6">
      <SignaturePacketComposer />
      <SignatureTemplateManager />
    </div>
  );
}
