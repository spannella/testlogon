import * as React from "react";
import { FilePen, FolderOpen } from "lucide-react";
import { toast } from "sonner";
import { Document, Page, pdfjs } from "react-pdf";
import "react-pdf/dist/Page/AnnotationLayer.css";
import "react-pdf/dist/Page/TextLayer.css";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SignatureDrawCanvas } from "@/components/SignatureDrawCanvas";
import { FilePickerDialog } from "@/pages/messages/FilePickerDialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  acknowledgeSignaturePacketLegalNotice,
  createSignaturePacket,
  createSignaturePacketField,
  deleteSignaturePacketField,
  downloadSignaturePacketFinalPdf,
  fillSignaturePacketField,
  getSignaturePacketDetail,
  markSignaturePacketDone,
  sendSignaturePacket,
  type SignaturePacketField,
  type SignatureFieldType,
  type SignatureOriginChannel,
  type SignaturePacketDetail,
  type SignatureInputMode,
} from "@/api/endpoints/signaturePackets";

// Configure the pdf.js worker for react-pdf. Vite's `new URL(..., import.meta.url)`
// pattern bundles the worker file and serves it from the same origin (avoids CORS).
pdfjs.GlobalWorkerOptions.workerSrc = new URL(
  "pdfjs-dist/build/pdf.worker.min.mjs",
  import.meta.url,
).toString();

const FIELD_TYPES: SignatureFieldType[] = ["signature", "initials", "date", "text"];

// Rendered width (px) of each PDF page in the editor canvas. Field coordinates are
// stored as normalized 0..1 floats, so overlays are positioned with CSS percentages
// and remain correct regardless of the actual rendered pixel size.
const PDF_PAGE_WIDTH = 640;

// Build a fetch-able URL for a source PDF path. In dev the backend serves files via
// the `/mock/s3/` proxy (same pattern used for image messages); already-absolute
// http(s) URLs are passed through unchanged.
function buildSourcePdfUrl(sourcePath: string | undefined): string | null {
  const trimmed = (sourcePath ?? "").trim();
  if (!trimmed) return null;
  if (/^https?:\/\//i.test(trimmed) || trimmed.startsWith("/mock/s3/")) return trimmed;
  return `/mock/s3/${trimmed.replace(/^\/+/, "")}`;
}

type ValidationError = string | null;
const SIGNATURE_MODE_PREF_KEY = "signature_packet_capture_mode_default";

function getDefaultDimensions(fieldType: SignatureFieldType): { width: number; height: number } {
  if (fieldType === "text") return { width: 0.32, height: 0.07 };
  if (fieldType === "date") return { width: 0.2, height: 0.05 };
  return { width: 0.22, height: 0.06 };
}

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

function validateFieldInput(field: SignaturePacketField, value: string, mode: SignatureInputMode, drawnRaw: string): ValidationError {
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
      if (Number.isNaN(x) || Number.isNaN(y) || x < 0 || x > 1 || y < 0 || y > 1) return "Drawn points must be within 0..1";
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

function statusChip(packet: SignaturePacketDetail | null): { label: string; className: string } {
  if (!packet) return { label: "draft", className: "bg-slate-100 text-slate-700" };
  if (packet.status === "completed") return { label: "completed", className: "bg-emerald-100 text-emerald-700" };
  if (packet.role === "signer") {
    if (packet.signer_status === "completed") return { label: "waiting on others", className: "bg-amber-100 text-amber-700" };
    return { label: "awaiting your signature", className: "bg-blue-100 text-blue-700" };
  }
  if (packet.status === "sent" || packet.status === "partially_signed") {
    return { label: "waiting on others", className: "bg-amber-100 text-amber-700" };
  }
  return { label: packet.status, className: "bg-slate-100 text-slate-700" };
}

function formatTs(ts?: string): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

export function SignaturePacketComposer() {
  const [sourcePath, setSourcePath] = React.useState("");
  const [pickerOpen, setPickerOpen] = React.useState(false);
  const [originChannel, setOriginChannel] = React.useState<SignatureOriginChannel>("share");
  const [packetId, setPacketId] = React.useState("");
  const [packet, setPacket] = React.useState<SignaturePacketDetail | null>(null);
  const [fieldType, setFieldType] = React.useState<SignatureFieldType>("signature");
  const [assignedSignerId, setAssignedSignerId] = React.useState<string>("unassigned");
  const [required, setRequired] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [statusMsg, setStatusMsg] = React.useState("");
  const [fillValues, setFillValues] = React.useState<Record<string, string>>({});
  const [fillErrors, setFillErrors] = React.useState<Record<string, string>>({});
  const [captureModes, setCaptureModes] = React.useState<Record<string, SignatureInputMode>>({});
  const [drawnValues, setDrawnValues] = React.useState<Record<string, string>>({});
  const [defaultCaptureMode, setDefaultCaptureMode] = React.useState<SignatureInputMode>((localStorage.getItem(SIGNATURE_MODE_PREF_KEY) as SignatureInputMode) || "typed");

  const canvasRef = React.useRef<HTMLDivElement | null>(null);
  const [numPages, setNumPages] = React.useState<number>(0);
  const [currentPage, setCurrentPage] = React.useState<number>(1);

  const pdfUrl = React.useMemo(
    () => buildSourcePdfUrl(packet?.source_path),
    [packet?.source_path],
  );

  const signerFields = React.useMemo(() => {
    if (!packet) return [];
    return packet.fields.filter((f) => isFieldAssignedToSigner(f));
  }, [packet]);

  const remainingRequiredCount = React.useMemo(() => {
    if (!packet || packet.role !== "signer") return 0;
    return signerFields.filter((field) => field.required && !field.filled_at).length;
  }, [packet, signerFields]);

  const loadPacket = React.useCallback(async (id: string) => {
    const trimmed = id.trim();
    if (!trimmed) {
      toast.error("Packet ID is required");
      return;
    }
    setBusy(true);
    try {
      const detail = await getSignaturePacketDetail(trimmed);
      setPacket(detail);
      setPacketId(detail.packet_id);
      const seeded: Record<string, string> = {};
      for (const field of detail.fields) {
        seeded[field.field_id] = typeof field.value === "string" ? field.value : "";
      }
      setFillValues(seeded);
      setFillErrors({});
      const modeSeed: Record<string, SignatureInputMode> = {};
      const drawnSeed: Record<string, string> = {};
      for (const field of detail.fields) {
        if (field.field_type === "signature" || field.field_type === "initials") {
          modeSeed[field.field_id] = (field.capture_mode as SignatureInputMode) || defaultCaptureMode;
          drawnSeed[field.field_id] = JSON.stringify((field.render_payload?.strokes as number[][] | undefined) ?? []);
        }
      }
      setCaptureModes(modeSeed);
      setDrawnValues(drawnSeed);
      setStatusMsg(`Loaded packet ${detail.packet_id}`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      toast.error(message);
    } finally {
      setBusy(false);
    }
  }, [defaultCaptureMode]);

  const createDraft = React.useCallback(async () => {
    if (!sourcePath.trim()) {
      toast.error("Source PDF path is required");
      return;
    }
    setBusy(true);
    try {
      const created = await createSignaturePacket({
        source_path: sourcePath.trim(),
        origin_channel: originChannel,
      });
      await loadPacket(created.packet_id);
      setStatusMsg(`Created draft ${created.packet_id}`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      toast.error(message);
    } finally {
      setBusy(false);
    }
  }, [loadPacket, originChannel, sourcePath]);

  const sendPacket = React.useCallback(async () => {
    if (!packet) {
      toast.error("Load a packet first");
      return;
    }
    setBusy(true);
    try {
      await sendSignaturePacket(packet.packet_id);
      await loadPacket(packet.packet_id);
      setStatusMsg("Packet sent");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      toast.error(message);
    } finally {
      setBusy(false);
    }
  }, [loadPacket, packet]);

  const onCanvasClick = React.useCallback(
    async (ev: React.MouseEvent<HTMLDivElement>, page = 1) => {
      if (!packet) {
        toast.error("Load a draft packet first");
        return;
      }
      if (packet.status !== "draft") {
        toast.error("Only draft packets are editable");
        return;
      }
      if (!packet.capabilities?.can_edit_fields) {
        toast.error("You are not allowed to edit fields for this packet");
        return;
      }
      // Coordinates are normalized 0..1 relative to the clicked page element so they
      // map correctly onto the rendered PDF page (or the placeholder fallback).
      const target = ev.currentTarget ?? canvasRef.current;
      if (!target) return;
      const rect = target.getBoundingClientRect();
      const x = Math.max(0, Math.min(0.98, (ev.clientX - rect.left) / Math.max(1, rect.width)));
      const y = Math.max(0, Math.min(0.98, (ev.clientY - rect.top) / Math.max(1, rect.height)));
      const dims = getDefaultDimensions(fieldType);

      setBusy(true);
      try {
        await createSignaturePacketField(packet.packet_id, {
          action: "create",
          page,
          x,
          y,
          width: dims.width,
          height: dims.height,
          field_type: fieldType,
          assigned_signer_id: assignedSignerId === "unassigned" ? undefined : assignedSignerId,
          required,
        });
        await loadPacket(packet.packet_id);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        toast.error(message);
      } finally {
        setBusy(false);
      }
    },
    [assignedSignerId, fieldType, loadPacket, packet, required],
  );

  const deleteField = React.useCallback(
    async (fieldId: string) => {
      if (!packet) return;
      setBusy(true);
      try {
        await deleteSignaturePacketField(packet.packet_id, fieldId);
        await loadPacket(packet.packet_id);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        toast.error(message);
      } finally {
        setBusy(false);
      }
    },
    [loadPacket, packet],
  );

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
        if ((field.field_type === "signature" || field.field_type === "initials") && mode === "drawn") {
          await fillSignaturePacketField(packet.packet_id, field.field_id, {
            input_mode: "drawn",
            drawn_strokes: parseDrawnStrokes(drawnRaw),
          });
        } else if (field.field_type === "signature" || field.field_type === "initials") {
          await fillSignaturePacketField(packet.packet_id, field.field_id, {
            input_mode: "typed",
            value: value.trim(),
          });
        } else {
          await fillSignaturePacketField(packet.packet_id, field.field_id, { value: value.trim() });
        }
        setFillErrors((prev) => {
          const next = { ...prev };
          delete next[field.field_id];
          return next;
        });
        await loadPacket(packet.packet_id);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        toast.error(message);
      } finally {
        setBusy(false);
      }
    },
    [captureModes, defaultCaptureMode, drawnValues, fillValues, loadPacket, packet],
  );

  const markDone = React.useCallback(async () => {
    if (!packet) return;
    setBusy(true);
    try {
      await markSignaturePacketDone(packet.packet_id);
      await loadPacket(packet.packet_id);
      setStatusMsg("Marked done");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      toast.error(message);
    } finally {
      setBusy(false);
    }
  }, [loadPacket, packet]);

  const downloadFinal = React.useCallback(async () => {
    if (!packet || packet.status !== "completed") return;
    try {
      await downloadSignaturePacketFinalPdf(packet.packet_id);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      toast.error(message);
    }
  }, [packet]);

  const signerCanFill = Boolean(packet?.role === "signer" && packet?.capabilities?.can_fill_fields);
  const legalNoticeRequired = Boolean(packet?.role === "signer" && packet?.legal_notice?.required);
  const chip = statusChip(packet);

  const acknowledgeLegalNotice = React.useCallback(async () => {
    if (!packet) return;
    setBusy(true);
    try {
      await acknowledgeSignaturePacketLegalNotice(packet.packet_id);
      await loadPacket(packet.packet_id);
      setStatusMsg("Legal notice accepted");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      toast.error(message);
    } finally {
      setBusy(false);
    }
  }, [loadPacket, packet]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FilePen className="h-5 w-5" />
          Document Signing
        </CardTitle>
        <CardDescription>Create and send signature packets for PDF documents</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
      <div>
        <h3 className="text-base font-semibold">Create signature form</h3>
        <p className="text-sm text-muted-foreground">
          Send a PDF for signature in three steps: choose the document, place signer fields, then send.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${chip.className}`} data-testid="packet-status-chip">
          {chip.label}
        </span>
        {packet?.status === "completed" && (
          <Button size="sm" onClick={() => void downloadFinal()} data-testid="final-download-btn">
            Download completed PDF
          </Button>
        )}
      </div>

      <div className="space-y-1">
        <Label className="text-sm font-medium">Step 1 · Choose the PDF to sign</Label>
        <div className="grid gap-3 md:grid-cols-[auto_1fr_auto_auto]">
          <Button type="button" variant="outline" onClick={() => setPickerOpen(true)} className="gap-2">
            <FolderOpen className="h-4 w-4" /> Choose PDF
          </Button>
          <Input
            placeholder="Source PDF path — or click Choose PDF"
            value={sourcePath}
            onChange={(e) => setSourcePath(e.target.value)}
          />
          <Select value={originChannel} onValueChange={(v) => setOriginChannel(v as SignatureOriginChannel)}>
            <SelectTrigger className="w-[160px]"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="share">Share link</SelectItem>
              <SelectItem value="message">In a message</SelectItem>
            </SelectContent>
          </Select>
          <Button onClick={createDraft} disabled={busy || !sourcePath.trim()}>Create draft</Button>
        </div>
        <p className="text-xs text-muted-foreground">
          Pick a PDF from your files, then “Create draft” to add signer fields and send.
        </p>
      </div>

      <details className="rounded-md border bg-muted/10 px-3 py-2">
        <summary className="cursor-pointer select-none text-sm text-muted-foreground">
          Resume an existing draft
        </summary>
        <div className="mt-2 grid gap-3 md:grid-cols-[1fr_auto]">
          <Input
            placeholder="Packet ID"
            value={packetId}
            onChange={(e) => setPacketId(e.target.value)}
          />
          <Button variant="outline" onClick={() => void loadPacket(packetId)} disabled={busy}>Load</Button>
        </div>
      </details>

      <div className="rounded-md border bg-muted/20 p-3 text-xs text-muted-foreground" data-testid="signature-status">
        {statusMsg || "Choose a PDF and create a draft to get started."}
      </div>

      {packet && (
        <div className="rounded-md border p-3" data-testid="packet-timeline">
          <div className="text-sm font-medium mb-2">Progress</div>
          <ul className="space-y-1 text-xs text-muted-foreground">
            <li>Draft created: {formatTs(packet?.created_at)}</li>
            <li>Sent: {formatTs(packet?.sent_at)}</li>
            <li>Completed: {formatTs(packet?.completed_at)}</li>
          </ul>
        </div>
      )}

      {signerCanFill && (
        <div className="rounded-md border p-3 space-y-2" data-testid="signer-fill-panel">
          <div className="text-sm font-medium">Signer fill</div>
          <div className="text-xs text-muted-foreground" data-testid="remaining-required">
            Remaining required fields: {remainingRequiredCount}
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
              <SelectTrigger className="w-[140px]"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="typed">typed</SelectItem>
                <SelectItem value="drawn">drawn</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <Button
            onClick={() => void markDone()}
            disabled={busy || remainingRequiredCount > 0 || legalNoticeRequired}
            data-testid="mark-done-btn"
          >
            Mark done
          </Button>
        </div>
      )}

      {packet?.role === "signer" && packet?.legal_notice && (
        <div className="rounded-md border p-3 space-y-2" data-testid="legal-notice-panel">
          <div className="text-sm font-medium">Legal notice</div>
          <div className="text-xs text-muted-foreground">Version: {packet.legal_notice.version}</div>
          <p className="text-sm">{packet.legal_notice.text}</p>
          {packet.legal_notice.required ? (
            <Button size="sm" onClick={() => void acknowledgeLegalNotice()} disabled={busy} data-testid="legal-notice-accept-btn">
              I acknowledge and agree
            </Button>
          ) : (
            <div className="text-xs text-emerald-700">Already accepted</div>
          )}
        </div>
      )}

      {packet && (
      <div className="space-y-3">
        {packet.role !== "signer" && (
          <div className="space-y-1">
            <Label className="text-sm font-medium">Step 2 · Place signature fields</Label>
            <p className="text-xs text-muted-foreground">
              Pick a field type and signer, then click on the document to drop the field.
            </p>
          </div>
        )}
      <div className="grid gap-4 lg:grid-cols-[320px_1fr]">
        <div className="space-y-3">
          <div className="space-y-2">
            <Label>Field type</Label>
            <Select value={fieldType} onValueChange={(v) => setFieldType(v as SignatureFieldType)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {FIELD_TYPES.map((ft) => <SelectItem key={ft} value={ft}>{ft}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label>Assigned signer</Label>
            <Select value={assignedSignerId} onValueChange={setAssignedSignerId}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="unassigned">Unassigned</SelectItem>
                {(packet?.signers ?? []).map((signer) => (
                  <SelectItem key={signer.signer_id} value={signer.signer_id}>
                    {signer.signer_id} ({signer.status})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={required} onChange={(e) => setRequired(e.target.checked)} />
            Required field
          </label>

          <div className="space-y-2">
            <Label>Fields</Label>
            <div className="max-h-72 space-y-2 overflow-auto rounded-md border p-2">
              {(packet?.fields ?? []).length === 0 && (
                <div className="text-xs text-muted-foreground">No fields yet.</div>
              )}
              {(packet?.fields ?? []).map((field) => {
                const editable = signerCanFill && !legalNoticeRequired && isFieldAssignedToSigner(field) && !field.filled_at;
                const currentValue = fillValues[field.field_id] ?? "";
                return (
                  <div key={field.field_id} className="rounded border p-2 text-xs space-y-2">
                    <div className="font-medium">{field.field_type}</div>
                    <div className="text-muted-foreground">{field.field_id}</div>
                    <div className="text-muted-foreground">
                      signer: {field.assigned_signer_id ?? "unassigned"} · {field.required ? "required" : "optional"}
                    </div>
                    {field.filled_at ? (
                      <div className="text-emerald-700">Filled ({field.capture_mode ?? "standard"})</div>
                    ) : editable ? (
                      <>
                        {(field.field_type === "signature" || field.field_type === "initials") && (
                          <Select
                            value={captureModes[field.field_id] ?? defaultCaptureMode}
                            onValueChange={(v) => setCaptureModes((prev) => ({ ...prev, [field.field_id]: v as SignatureInputMode }))}
                          >
                            <SelectTrigger data-testid={`field-mode-${field.field_id}`}><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="typed">typed</SelectItem>
                              <SelectItem value="drawn">drawn</SelectItem>
                            </SelectContent>
                          </Select>
                        )}
                        {(field.field_type !== "signature" && field.field_type !== "initials") || (captureModes[field.field_id] ?? defaultCaptureMode) === "typed" ? (
                          <Input
                            type={field.field_type === "date" ? "date" : "text"}
                            value={currentValue}
                            onChange={(e) => {
                              const value = e.target.value;
                              setFillValues((prev) => ({ ...prev, [field.field_id]: value }));
                              const mode = captureModes[field.field_id] ?? defaultCaptureMode;
                              const drawnRaw = drawnValues[field.field_id] ?? "";
                              const err = validateFieldInput(field, value, mode, drawnRaw);
                              setFillErrors((prev) => ({ ...prev, [field.field_id]: err ?? "" }));
                            }}
                            placeholder={`Enter ${field.field_type}`}
                            data-testid={`field-input-${field.field_id}`}
                          />
                        ) : (
                          <SignatureDrawCanvas
                            testId={`field-drawn-${field.field_id}`}
                            onChange={(serialized) => {
                              setDrawnValues((prev) => ({ ...prev, [field.field_id]: serialized }));
                              const mode = captureModes[field.field_id] ?? defaultCaptureMode;
                              const err = validateFieldInput(field, currentValue, mode, serialized);
                              setFillErrors((prev) => ({ ...prev, [field.field_id]: err ?? "" }));
                            }}
                          />
                        )}
                        {fillErrors[field.field_id] && (
                          <div className="text-red-600" data-testid={`field-error-${field.field_id}`}>
                            {fillErrors[field.field_id]}
                          </div>
                        )}
                        <Button
                          size="sm"
                          onClick={() => void submitFill(field)}
                          disabled={busy}
                          data-testid={`field-submit-${field.field_id}`}
                        >
                          Save value
                        </Button>
                      </>
                    ) : (
                      <div className="text-muted-foreground">Read-only for current viewer</div>
                    )}
                    {packet?.capabilities?.can_edit_fields && (
                      <Button
                        size="sm"
                        variant="destructive"
                        className="h-7"
                        onClick={() => void deleteField(field.field_id)}
                        disabled={busy}
                      >
                        Delete
                      </Button>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Document preview — click to place a field</span>
            <span>Status: {packet?.status ?? "draft"}</span>
          </div>
          <div
            ref={canvasRef}
            data-testid="signature-canvas"
            className="relative max-h-[640px] overflow-auto rounded-md border bg-slate-100"
          >
            {pdfUrl ? (
              <Document
                file={pdfUrl}
                onLoadSuccess={({ numPages: n }) => setNumPages(n)}
                onLoadError={(err) =>
                  toast.error(`Failed to load PDF: ${err?.message ?? "unknown error"}`)
                }
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
                  <div
                    key={pageNum}
                    className="relative shadow-sm"
                    onMouseEnter={() => setCurrentPage(pageNum)}
                    onClick={(ev) => void onCanvasClick(ev, pageNum)}
                  >
                    <Page
                      pageNumber={pageNum}
                      width={PDF_PAGE_WIDTH}
                      renderAnnotationLayer={false}
                      renderTextLayer={false}
                    />
                    {(packet?.fields ?? [])
                      .filter((field) => (field.page ?? 1) === pageNum)
                      .map((field) => (
                        <div
                          key={field.field_id}
                          className="absolute rounded border border-blue-600 bg-blue-100/60 px-1 text-[10px] text-blue-900"
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
              <div
                onClick={(ev) => void onCanvasClick(ev, currentPage)}
                className="relative h-[520px] rounded-md border border-dashed bg-slate-50"
              >
                <span className="pointer-events-none absolute inset-0 flex items-center justify-center text-xs text-muted-foreground">
                  {packet ? "No source PDF to display" : "Load a packet to see the document"}
                </span>
                {(packet?.fields ?? []).map((field) => (
                  <div
                    key={field.field_id}
                    className="absolute rounded border border-blue-600 bg-blue-100/60 px-1 text-[10px] text-blue-900"
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
            )}
          </div>
        </div>
      </div>

      {packet.role !== "signer" && packet.capabilities?.can_send && (
        <div className="space-y-1 border-t pt-3">
          <Label className="text-sm font-medium">Step 3 · Send for signature</Label>
          <p className="text-xs text-muted-foreground">
            When your fields are placed, send the document to the signers.
          </p>
          <Button onClick={() => void sendPacket()} disabled={busy || !packet.capabilities?.can_send}>
            Send packet
          </Button>
        </div>
      )}
      </div>
      )}

      <FilePickerDialog
        open={pickerOpen}
        onClose={() => setPickerOpen(false)}
        showPermission={false}
        onSelect={(entry) => {
          setSourcePath(entry.path);
          setPickerOpen(false);
        }}
      />
      </CardContent>
    </Card>
  );
}
