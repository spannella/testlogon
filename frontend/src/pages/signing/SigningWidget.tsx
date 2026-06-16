import * as React from "react";
import { toast } from "sonner";
import { Document, Page, pdfjs } from "react-pdf";
import "react-pdf/dist/Page/AnnotationLayer.css";
import "react-pdf/dist/Page/TextLayer.css";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SignatureDrawCanvas } from "@/components/SignatureDrawCanvas";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  acknowledgeSignaturePacketLegalNotice,
  acknowledgePublicSigningLegalNotice,
  fillSignaturePacketField,
  fillPublicSigningField,
  getSignaturePacketDetail,
  getPublicSigningDetail,
  markSignaturePacketDone,
  markPublicSigningDone,
  type SignaturePacketField,
  type SignaturePacketDetail,
  type SignatureInputMode,
} from "@/api/endpoints/signaturePackets";

// Configure the pdf.js worker (same pattern as SignaturePacketComposer).
pdfjs.GlobalWorkerOptions.workerSrc = new URL(
  "pdfjs-dist/build/pdf.worker.min.mjs",
  import.meta.url,
).toString();

const PDF_PAGE_WIDTH = 640;
const SIGNATURE_MODE_PREF_KEY = "signature_packet_capture_mode_default";

function buildSourcePdfUrl(sourcePath: string | undefined): string | null {
  const trimmed = (sourcePath ?? "").trim();
  if (!trimmed) return null;
  if (/^https?:\/\//i.test(trimmed) || trimmed.startsWith("/mock/s3/")) return trimmed;
  return `/mock/s3/${trimmed.replace(/^\/+/, "")}`;
}

type ValidationError = string | null;

function parseDrawnStrokes(raw: string): number[][] {
  if (!raw.trim()) return [];
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(Array.isArray) as number[][];
  } catch {
    return [];
  }
}

function validateFieldInput(
  field: SignaturePacketField,
  value: string,
  mode: SignatureInputMode,
  drawnRaw: string,
): ValidationError {
  const trimmed = value.trim();
  if (field.field_type === "signature" || field.field_type === "initials") {
    if (mode === "typed") {
      if (!trimmed) return "Value is required";
      if (trimmed.length > 64) return "Max length is 64";
      return null;
    }
    const strokes = parseDrawnStrokes(drawnRaw);
    if (strokes.length < 2) return "Drawn mode needs JSON points, e.g. [[0.1,0.2],[0.2,0.3]]";
    if (strokes.length > 20) return "Max points is 20";
    for (const point of strokes) {
      if (!Array.isArray(point) || point.length !== 2) return "Each point must be [x,y]";
      const x = Number(point[0]);
      const y = Number(point[1]);
      if (Number.isNaN(x) || Number.isNaN(y) || x < 0 || x > 1 || y < 0 || y > 1) {
        return "Drawn points must be within 0..1";
      }
    }
    return null;
  }
  if (field.field_type === "date") {
    if (!trimmed) return "Date is required";
    if (!/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) return "Use YYYY-MM-DD";
    return null;
  }
  if (field.field_type === "text") {
    if (field.required && !trimmed) return "Value is required";
    if (trimmed.length > 500) return "Max length is 500";
    return null;
  }
  return null;
}

function isFieldAssignedToSigner(field: SignaturePacketField): boolean {
  return Boolean(field.is_assigned_to_viewer);
}

/**
 * SigningWidget — reusable signer-fill workflow (SUX-006).
 *
 * Drives either an authenticated packet (`packetId`) or a public token (`token`).
 * Renders the PDF + assigned fields, lets the signer fill required fields,
 * acknowledge the legal notice, and mark done. Reuses the same field-fill
 * components as SignaturePacketComposer (no duplicate signature-capture logic).
 *
 * On completion calls `onCompleted()` (used by both the in-app inbox and the
 * public page; the public page also posts a `signing:completed` window message
 * for iframe hosts).
 */
export function SigningWidget({
  packetId,
  token,
  onCompleted,
  compact = false,
}: {
  packetId?: string;
  token?: string;
  onCompleted?: (packet: SignaturePacketDetail) => void;
  compact?: boolean;
}) {
  const isPublic = Boolean(token);

  const [packet, setPacket] = React.useState<SignaturePacketDetail | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [loadError, setLoadError] = React.useState<{ status: number; message: string } | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [fillValues, setFillValues] = React.useState<Record<string, string>>({});
  const [fillErrors, setFillErrors] = React.useState<Record<string, string>>({});
  const [captureModes, setCaptureModes] = React.useState<Record<string, SignatureInputMode>>({});
  const [drawnValues, setDrawnValues] = React.useState<Record<string, string>>({});
  const [defaultCaptureMode, setDefaultCaptureMode] = React.useState<SignatureInputMode>(
    (localStorage.getItem(SIGNATURE_MODE_PREF_KEY) as SignatureInputMode) || "typed",
  );
  const [numPages, setNumPages] = React.useState(0);

  const pdfUrl = React.useMemo(() => buildSourcePdfUrl(packet?.source_path), [packet?.source_path]);

  const signerFields = React.useMemo(() => {
    if (!packet) return [];
    return packet.fields.filter((f) => isFieldAssignedToSigner(f));
  }, [packet]);

  const remainingRequiredCount = React.useMemo(() => {
    if (!packet) return 0;
    return signerFields.filter((field) => field.required && !field.filled_at).length;
  }, [packet, signerFields]);

  const seedFromDetail = React.useCallback(
    (detail: SignaturePacketDetail) => {
      const seeded: Record<string, string> = {};
      const modeSeed: Record<string, SignatureInputMode> = {};
      const drawnSeed: Record<string, string> = {};
      for (const field of detail.fields) {
        seeded[field.field_id] = typeof field.value === "string" ? field.value : "";
        if (field.field_type === "signature" || field.field_type === "initials") {
          modeSeed[field.field_id] = (field.capture_mode as SignatureInputMode) || defaultCaptureMode;
          drawnSeed[field.field_id] = JSON.stringify(
            (field.render_payload?.strokes as number[][] | undefined) ?? [],
          );
        }
      }
      setFillValues(seeded);
      setFillErrors({});
      setCaptureModes(modeSeed);
      setDrawnValues(drawnSeed);
    },
    [defaultCaptureMode],
  );

  const loadPacket = React.useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const detail = isPublic
        ? await getPublicSigningDetail(token as string)
        : await getSignaturePacketDetail(packetId as string);
      setPacket(detail);
      seedFromDetail(detail);
    } catch (err) {
      const status = (err as { status?: number })?.status ?? 0;
      const message = err instanceof Error ? err.message : String(err);
      setLoadError({ status, message });
    } finally {
      setLoading(false);
    }
  }, [isPublic, packetId, seedFromDetail, token]);

  React.useEffect(() => {
    void loadPacket();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [packetId, token]);

  const submitFill = React.useCallback(
    async (field: SignaturePacketField) => {
      if (!packet) return;
      const value = fillValues[field.field_id] ?? "";
      const mode = captureModes[field.field_id] ?? defaultCaptureMode;
      const drawnRaw = drawnValues[field.field_id] ?? "";
      const err = validateFieldInput(field, value, mode, drawnRaw);
      if (err) {
        setFillErrors((prev) => ({ ...prev, [field.field_id]: err }));
        return;
      }
      setBusy(true);
      try {
        let body: { value?: string; input_mode?: SignatureInputMode; drawn_strokes?: number[][] };
        if ((field.field_type === "signature" || field.field_type === "initials") && mode === "drawn") {
          body = { input_mode: "drawn", drawn_strokes: parseDrawnStrokes(drawnRaw) };
        } else if (field.field_type === "signature" || field.field_type === "initials") {
          body = { input_mode: "typed", value: value.trim() };
        } else {
          body = { value: value.trim() };
        }
        if (isPublic) {
          await fillPublicSigningField(token as string, field.field_id, body);
        } else {
          await fillSignaturePacketField(packet.packet_id, field.field_id, body);
        }
        setFillErrors((prev) => {
          const next = { ...prev };
          delete next[field.field_id];
          return next;
        });
        await loadPacket();
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        toast.error(message);
      } finally {
        setBusy(false);
      }
    },
    [captureModes, defaultCaptureMode, drawnValues, fillValues, isPublic, loadPacket, packet, token],
  );

  const acknowledgeLegalNotice = React.useCallback(async () => {
    if (!packet) return;
    setBusy(true);
    try {
      if (isPublic) {
        await acknowledgePublicSigningLegalNotice(token as string);
      } else {
        await acknowledgeSignaturePacketLegalNotice(packet.packet_id);
      }
      await loadPacket();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      toast.error(message);
    } finally {
      setBusy(false);
    }
  }, [isPublic, loadPacket, packet, token]);

  const markDone = React.useCallback(async () => {
    if (!packet) return;
    setBusy(true);
    try {
      if (isPublic) {
        await markPublicSigningDone(token as string);
      } else {
        await markSignaturePacketDone(packet.packet_id);
      }
      const refreshed = isPublic
        ? null
        : await getSignaturePacketDetail(packet.packet_id).catch(() => null);
      if (refreshed) setPacket(refreshed);
      toast.success("Signing complete");
      onCompleted?.(refreshed ?? packet);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      toast.error(message);
    } finally {
      setBusy(false);
    }
  }, [isPublic, onCompleted, packet, token]);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center text-sm text-muted-foreground">
        Loading document…
      </div>
    );
  }

  if (loadError) {
    const friendly =
      loadError.status === 403
        ? "This signing link is invalid, expired, or has already been used."
        : loadError.status === 404
          ? "This signing request could not be found."
          : loadError.message || "Unable to load this signing request.";
    return (
      <div
        className="rounded-md border border-amber-200 bg-amber-50 p-6 text-center"
        data-testid="signing-terminal-state"
      >
        <div className="text-base font-semibold text-amber-900">Signing unavailable</div>
        <p className="mt-2 text-sm text-amber-800">{friendly}</p>
      </div>
    );
  }

  if (!packet) return null;

  const signerCanFill = Boolean(packet.role === "signer" && packet.capabilities?.can_fill_fields);
  const legalNoticeRequired = Boolean(packet.role === "signer" && packet.legal_notice?.required);
  const alreadyCompleted = packet.status === "completed" || packet.signer_status === "completed";

  return (
    <div className={compact ? "space-y-4" : "grid gap-4 lg:grid-cols-[1fr_360px]"}>
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>Document preview</span>
          <span>status: {packet.status}</span>
        </div>
        <div
          data-testid="signing-canvas"
          className="relative max-h-[640px] overflow-auto rounded-md border bg-slate-100"
        >
          {pdfUrl ? (
            <Document
              file={pdfUrl}
              onLoadSuccess={({ numPages: n }) => setNumPages(n)}
              onLoadError={(err) => toast.error(`Failed to load PDF: ${err?.message ?? "unknown error"}`)}
              loading={
                <div className="flex h-[520px] items-center justify-center text-xs text-muted-foreground">
                  Loading PDF…
                </div>
              }
              error={
                <div className="flex h-[520px] items-center justify-center text-xs text-destructive">
                  Unable to display this PDF.
                </div>
              }
              className="flex flex-col items-center gap-3 p-2"
            >
              {Array.from({ length: numPages }, (_, i) => i + 1).map((pageNum) => (
                <div key={pageNum} className="relative shadow-sm">
                  <Page
                    pageNumber={pageNum}
                    width={PDF_PAGE_WIDTH}
                    renderAnnotationLayer={false}
                    renderTextLayer={false}
                  />
                  {packet.fields
                    .filter((field) => (field.page ?? 1) === pageNum)
                    .map((field) => (
                      <div
                        key={field.field_id}
                        className={`absolute rounded border px-1 text-[10px] ${
                          field.filled_at
                            ? "border-emerald-600 bg-emerald-100/60 text-emerald-900"
                            : "border-blue-600 bg-blue-100/60 text-blue-900"
                        }`}
                        style={{
                          left: `${Math.max(0, field.x) * 100}%`,
                          top: `${Math.max(0, field.y) * 100}%`,
                          width: `${Math.max(0.05, field.width) * 100}%`,
                          height: `${Math.max(0.03, field.height) * 100}%`,
                        }}
                      >
                        {field.field_type}
                      </div>
                    ))}
                </div>
              ))}
            </Document>
          ) : (
            <div className="relative h-[520px] rounded-md border border-dashed bg-slate-50">
              <span className="pointer-events-none absolute inset-0 flex items-center justify-center text-xs text-muted-foreground">
                No source PDF to display
              </span>
            </div>
          )}
        </div>
      </div>

      <div className="space-y-3">
        {packet.legal_notice && (
          <div className="rounded-md border p-3 space-y-2" data-testid="signing-legal-notice">
            <div className="text-sm font-medium">Legal notice</div>
            <div className="text-xs text-muted-foreground">Version: {packet.legal_notice.version}</div>
            <p className="text-sm">{packet.legal_notice.text}</p>
            {legalNoticeRequired ? (
              <Button
                size="sm"
                onClick={() => void acknowledgeLegalNotice()}
                disabled={busy}
                data-testid="signing-legal-accept-btn"
              >
                I acknowledge and agree
              </Button>
            ) : (
              <div className="text-xs text-emerald-700">Accepted</div>
            )}
          </div>
        )}

        {alreadyCompleted ? (
          <div
            className="rounded-md border border-emerald-200 bg-emerald-50 p-4 text-center"
            data-testid="signing-completed"
          >
            <div className="text-sm font-semibold text-emerald-800">All set — your signature is recorded.</div>
            <p className="mt-1 text-xs text-emerald-700">You can safely close this page.</p>
          </div>
        ) : signerCanFill ? (
          <div className="rounded-md border p-3 space-y-3" data-testid="signing-fill-panel">
            <div className="flex items-center justify-between">
              <div className="text-sm font-medium">Fill your fields</div>
              <span className="text-xs text-muted-foreground" data-testid="signing-remaining">
                {remainingRequiredCount} required left
              </span>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span>Default signature input:</span>
              <Select
                value={defaultCaptureMode}
                onValueChange={(v) => {
                  const next = v as SignatureInputMode;
                  setDefaultCaptureMode(next);
                  localStorage.setItem(SIGNATURE_MODE_PREF_KEY, next);
                }}
              >
                <SelectTrigger className="w-[120px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="typed">typed</SelectItem>
                  <SelectItem value="drawn">drawn</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="max-h-[360px] space-y-2 overflow-auto">
              {signerFields.length === 0 && (
                <div className="text-xs text-muted-foreground">No fields assigned to you.</div>
              )}
              {signerFields.map((field) => {
                const editable = !legalNoticeRequired && !field.filled_at;
                const currentValue = fillValues[field.field_id] ?? "";
                const isSig = field.field_type === "signature" || field.field_type === "initials";
                const mode = captureModes[field.field_id] ?? defaultCaptureMode;
                return (
                  <div key={field.field_id} className="rounded border p-2 text-xs space-y-2">
                    <div className="font-medium">
                      {field.field_type} {field.required ? "· required" : "· optional"}
                    </div>
                    {field.filled_at ? (
                      <div className="text-emerald-700">Filled</div>
                    ) : editable ? (
                      <>
                        {isSig && (
                          <Select
                            value={mode}
                            onValueChange={(v) =>
                              setCaptureModes((prev) => ({ ...prev, [field.field_id]: v as SignatureInputMode }))
                            }
                          >
                            <SelectTrigger data-testid={`signing-field-mode-${field.field_id}`}>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="typed">typed</SelectItem>
                              <SelectItem value="drawn">drawn</SelectItem>
                            </SelectContent>
                          </Select>
                        )}
                        {!isSig || mode === "typed" ? (
                          <Input
                            type={field.field_type === "date" ? "date" : "text"}
                            value={currentValue}
                            onChange={(e) => {
                              const value = e.target.value;
                              setFillValues((prev) => ({ ...prev, [field.field_id]: value }));
                              const drawnRaw = drawnValues[field.field_id] ?? "";
                              const verr = validateFieldInput(field, value, mode, drawnRaw);
                              setFillErrors((prev) => ({ ...prev, [field.field_id]: verr ?? "" }));
                            }}
                            placeholder={`Enter ${field.field_type}`}
                            data-testid={`signing-field-input-${field.field_id}`}
                          />
                        ) : (
                          <SignatureDrawCanvas
                            testId={`signing-field-drawn-${field.field_id}`}
                            onChange={(serialized) => {
                              setDrawnValues((prev) => ({ ...prev, [field.field_id]: serialized }));
                              const verr = validateFieldInput(field, currentValue, mode, serialized);
                              setFillErrors((prev) => ({ ...prev, [field.field_id]: verr ?? "" }));
                            }}
                          />
                        )}
                        {fillErrors[field.field_id] && (
                          <div className="text-red-600" data-testid={`signing-field-error-${field.field_id}`}>
                            {fillErrors[field.field_id]}
                          </div>
                        )}
                        <Button
                          size="sm"
                          onClick={() => void submitFill(field)}
                          disabled={busy}
                          data-testid={`signing-field-submit-${field.field_id}`}
                        >
                          Save
                        </Button>
                      </>
                    ) : (
                      <div className="text-muted-foreground">Read-only</div>
                    )}
                  </div>
                );
              })}
            </div>

            <Button
              className="w-full"
              onClick={() => void markDone()}
              disabled={busy || remainingRequiredCount > 0 || legalNoticeRequired}
              data-testid="signing-mark-done-btn"
            >
              Complete signing
            </Button>
            {(remainingRequiredCount > 0 || legalNoticeRequired) && (
              <p className="text-center text-xs text-muted-foreground">
                {legalNoticeRequired
                  ? "Accept the legal notice to continue."
                  : "Fill all required fields to complete."}
              </p>
            )}
          </div>
        ) : (
          <div className="rounded-md border p-3 text-sm text-muted-foreground" data-testid="signing-no-action">
            There is nothing for you to sign right now.
          </div>
        )}
      </div>
    </div>
  );
}

export default SigningWidget;
