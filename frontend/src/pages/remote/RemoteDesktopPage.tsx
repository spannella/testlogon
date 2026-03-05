import * as React from "react";
import { useNavigate } from "react-router-dom";
import { Expand, MonitorSmartphone, Power, RotateCcw, Unplug } from "lucide-react";

import { ApiError } from "@/api/client";
import {
  createVncSession,
  deleteVncSession,
  getVncTransferFallback,
  type CreateVncSessionResponse,
  type VncTransferFallbackResponse,
} from "@/api/endpoints/vnc";
import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";

const STORAGE_KEY = "remote_desktop_form_v1";
const RETRY_DELAYS_MS = [1000, 2000, 5000] as const;
const MAX_CLIPBOARD_CHARS = 20_000;
const MAX_TRANSFER_FILE_BYTES = 50 * 1024 * 1024;
const ACTIVITY_HEARTBEAT_MS = 5_000;
const DEFAULT_TIMEOUT_POLICY = {
  idle_timeout_seconds: 300,
  max_session_duration_seconds: 3600,
  warning_seconds: 60,
};

type AuthInputMode = "session_token" | "password";
type ConnectionState = "disconnected" | "connecting" | "connected" | "failed";

type FormValues = {
  targetId: string;
  host: string;
  port: string;
  displayLabel: string;
  authMode: AuthInputMode;
};

type FormErrors = {
  targetId?: string;
  host?: string;
  port?: string;
};

type UploadState = "queued" | "uploading" | "success" | "failure";

type TransferItem = {
  id: string;
  name: string;
  size: number;
  state: UploadState;
  progress: number;
  error?: string;
};

type RfbLike = {
  scaleViewport?: boolean;
  viewOnly?: boolean;
  addEventListener: (event: string, handler: EventListener) => void;
  disconnect: () => void;
  sendCtrlAltDel: () => void;
  clipboardPasteFrom?: (text: string) => void;
};

const DEFAULT_FORM: FormValues = {
  targetId: "",
  host: "",
  port: "",
  displayLabel: "",
  authMode: "session_token",
};

const ERROR_MESSAGES: Record<string, string> = {
  VNC_AUTH_UNAUTHORIZED: "You are not authorized to access this VNC target.",
  VNC_TARGET_NOT_FOUND: "Target not found. Select a registered target ID.",
  VNC_TARGET_UNREACHABLE: "The VNC target is currently unreachable.",
  VNC_BRIDGE_TIMEOUT: "Bridge timed out while connecting. Try again.",
  VNC_TOKEN_EXPIRED: "Session token expired. Start a new session.",
  VNC_TOKEN_INVALID: "Session token is invalid. Start a new session.",
  VNC_SESSION_NOT_FOUND: "Session not found. Start a new session.",
  VNC_SESSION_TERMINATED: "Session terminated by policy or timeout.",
  VNC_RATE_LIMITED: "Too many VNC session attempts. Please wait and retry.",
  VNC_INTERNAL_ERROR: "Unexpected VNC error. Retry and contact support if it persists.",
};

const TRANSIENT_ERROR_CODES = new Set(["VNC_TARGET_UNREACHABLE", "VNC_BRIDGE_TIMEOUT", "VNC_RATE_LIMITED", "VNC_INTERNAL_ERROR"]);
const SESSION_EXPIRED_CODES = new Set(["VNC_TOKEN_EXPIRED", "VNC_SESSION_TERMINATED", "VNC_SESSION_NOT_FOUND"]);

function loadPersistedForm(): FormValues {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_FORM;
    const parsed = JSON.parse(raw) as Partial<FormValues>;
    return {
      targetId: parsed.targetId ?? "",
      host: parsed.host ?? "",
      port: parsed.port ?? "",
      displayLabel: parsed.displayLabel ?? "",
      authMode: parsed.authMode === "password" ? "password" : "session_token",
    };
  } catch {
    return DEFAULT_FORM;
  }
}

function persistForm(values: FormValues): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(values));
  } catch {
    // ignore storage errors
  }
}

function extractApiErrorCode(error: unknown): string | null {
  if (!(error instanceof ApiError)) return null;
  const body = error.body as { detail?: { error?: { code?: string } } } | undefined;
  return body?.detail?.error?.code ?? null;
}

function validate(values: FormValues): FormErrors {
  const errors: FormErrors = {};
  if (!values.targetId.trim()) {
    errors.targetId = "Target ID is required.";
  }

  if (values.host.trim() && !/^[a-zA-Z0-9._:-]+$/.test(values.host.trim())) {
    errors.host = "Host contains invalid characters.";
  }

  if (values.port.trim()) {
    const asNum = Number(values.port);
    if (!Number.isInteger(asNum) || asNum < 1 || asNum > 65535) {
      errors.port = "Port must be an integer between 1 and 65535.";
    }
  }

  return errors;
}

function withConnectParams(wsUrl: string, connectParams: Record<string, string>): string {
  const token = connectParams.token;
  if (!token) return wsUrl;
  const separator = wsUrl.includes("?") ? "&" : "?";
  return `${wsUrl}${separator}token=${encodeURIComponent(token)}`;
}

function statusVariant(state: ConnectionState): "secondary" | "default" | "destructive" {
  if (state === "connected") return "default";
  if (state === "failed") return "destructive";
  return "secondary";
}

declare global {
  interface Window {
    __TEST_RFB__?: new (target: Element, url: string, options?: Record<string, unknown>) => RfbLike;
  }
}

async function loadRfbConstructor(): Promise<new (target: Element, url: string, options?: Record<string, unknown>) => RfbLike> {
  if (typeof window !== "undefined" && window.__TEST_RFB__) {
    return window.__TEST_RFB__;
  }
  // @ts-expect-error URL import resolved at runtime in browser
  const mod = await import(/* @vite-ignore */ "https://esm.sh/@novnc/novnc@1.5.0/lib/rfb.js");
  return mod.default as new (target: Element, url: string, options?: Record<string, unknown>) => RfbLike;
}

export default function RemoteDesktopPage() {
  const navigate = useNavigate();
  const [form, setForm] = React.useState<FormValues>(() => loadPersistedForm());
  const [errors, setErrors] = React.useState<FormErrors>({});
  const [status, setStatus] = React.useState<string>("");
  const [session, setSession] = React.useState<CreateVncSessionResponse | null>(null);
  const [connectionState, setConnectionState] = React.useState<ConnectionState>("disconnected");
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const [isDisconnecting, setIsDisconnecting] = React.useState(false);
  const [retryAttempt, setRetryAttempt] = React.useState(0);
  const [nextRetryAt, setNextRetryAt] = React.useState<number | null>(null);
  const [lastErrorCode, setLastErrorCode] = React.useState<string | null>(null);
  const [sessionExpired, setSessionExpired] = React.useState(false);
  const [timeoutWarningSeconds, setTimeoutWarningSeconds] = React.useState<number | null>(null);
  const [retryClock, setRetryClock] = React.useState(() => Date.now());
  const [clipboardText, setClipboardText] = React.useState("");
  const [remoteClipboardText, setRemoteClipboardText] = React.useState("");
  const [clipboardStatus, setClipboardStatus] = React.useState("");
  const [isReadingClipboard, setIsReadingClipboard] = React.useState(false);
  const [isSendingClipboard, setIsSendingClipboard] = React.useState(false);
  const [clipboardPermission, setClipboardPermission] = React.useState<"unknown" | "granted" | "denied" | "unsupported">("unknown");
  const [transferItems, setTransferItems] = React.useState<TransferItem[]>([]);
  const [transferStatus, setTransferStatus] = React.useState("");
  const [isDragActive, setIsDragActive] = React.useState(false);
  const [fallbackTransfer, setFallbackTransfer] = React.useState<VncTransferFallbackResponse | null>(null);
  const [fallbackStatus, setFallbackStatus] = React.useState("");
  const [isLoadingFallback, setIsLoadingFallback] = React.useState(false);

  const viewerRef = React.useRef<HTMLDivElement | null>(null);
  const fileInputRef = React.useRef<HTMLInputElement | null>(null);
  const rfbRef = React.useRef<RfbLike | null>(null);
  const lastActivityAtRef = React.useRef<number>(Date.now());
  const policyTimeoutHandledRef = React.useRef(false);

  const capabilities = session?.capabilities ?? {
    clipboard: false,
    file_transfer: false,
    drag_drop_upload: false,
  };

  const setField = <K extends keyof FormValues>(key: K, value: FormValues[K]) => {
    setForm((prev) => {
      const next = { ...prev, [key]: value };
      persistForm(next);
      return next;
    });
  };

  const resetFailureUi = React.useCallback(() => {
    setRetryAttempt(0);
    setNextRetryAt(null);
    setLastErrorCode(null);
    setSessionExpired(false);
    setTimeoutWarningSeconds(null);
    policyTimeoutHandledRef.current = false;
  }, []);

  const classifyError = React.useCallback((error: unknown) => {
    const code = extractApiErrorCode(error);
    const message = code && ERROR_MESSAGES[code]
      ? `${ERROR_MESSAGES[code]} (${code})`
      : error instanceof Error
        ? error.message
        : "Unexpected VNC failure.";
    return { code, message };
  }, []);

  const logClipboardTelemetry = React.useCallback((action: string, outcome: "success" | "failure", detail: string) => {
    console.info("vnc_clipboard_event", { action, outcome, detail });
  }, []);

  const connectViewer = React.useCallback(async (created: CreateVncSessionResponse) => {
    if (!viewerRef.current) {
      throw new Error("Viewer container unavailable.");
    }

    setConnectionState("connecting");
    const url = withConnectParams(created.ws_url, created.connect_params || {});

    const RFB = await loadRfbConstructor();
    const rfb = new RFB(viewerRef.current, url, {});
    rfb.scaleViewport = true;
    rfb.viewOnly = false;
    rfb.addEventListener("connect", () => {
      lastActivityAtRef.current = Date.now();
      setConnectionState("connected");
      setStatus("Connected to remote VNC viewer.");
      resetFailureUi();
    });
    rfb.addEventListener("disconnect", () => {
      setConnectionState("disconnected");
      setTimeoutWarningSeconds(null);
      setStatus("Disconnected from remote VNC viewer.");
    });
    rfb.addEventListener("clipboard", (event: Event) => {
      const clipboardEvent = event as CustomEvent<{ text?: string }>;
      const text = clipboardEvent.detail?.text ?? "";
      setRemoteClipboardText(text);
      if (text) {
        setClipboardStatus("Remote clipboard updated from active session.");
      }
    });
    rfbRef.current = rfb;
  }, [resetFailureUi]);

  const bootstrapAndConnect = React.useCallback(async () => {
    const created = await createVncSession({ target_id: form.targetId.trim() });
    setSession(created);
    setStatus("Session created. Connecting viewer...");
    await connectViewer(created);
  }, [connectViewer, form.targetId]);

  const scheduleRetry = React.useCallback(() => {
    const delay: number = RETRY_DELAYS_MS[Math.min(retryAttempt, RETRY_DELAYS_MS.length - 1)] ?? 5000;
    setRetryAttempt((prev) => prev + 1);
    setNextRetryAt(Date.now() + delay);
  }, [retryAttempt]);

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const nextErrors = validate(form);
    setErrors(nextErrors);
    if (Object.keys(nextErrors).length > 0) {
      setStatus("Fix validation errors and try again.");
      return;
    }

    setIsSubmitting(true);
    setStatus("Creating VNC session...");
    setConnectionState("connecting");
    lastActivityAtRef.current = Date.now();
    resetFailureUi();
    try {
      await bootstrapAndConnect();
    } catch (error) {
      setConnectionState("failed");
      const mapped = classifyError(error);
      setLastErrorCode(mapped.code);
      setStatus(mapped.message);
      if (mapped.code && SESSION_EXPIRED_CODES.has(mapped.code)) {
        setSessionExpired(true);
      }
      if (mapped.code && TRANSIENT_ERROR_CODES.has(mapped.code)) {
        scheduleRetry();
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const onReconnect = async () => {
    if (nextRetryAt && retryClock < nextRetryAt) {
      const waitMs = nextRetryAt - retryClock;
      setStatus(`Retry available in ${Math.max(1, Math.ceil(waitMs / 1000))}s.`);
      return;
    }
    setIsSubmitting(true);
    setConnectionState("connecting");
    setStatus("Retrying connection...");
    lastActivityAtRef.current = Date.now();
    try {
      if (session) {
        await connectViewer(session);
      } else {
        await bootstrapAndConnect();
      }
    } catch (error) {
      setConnectionState("failed");
      const mapped = classifyError(error);
      setLastErrorCode(mapped.code);
      setStatus(mapped.message);
      if (mapped.code && SESSION_EXPIRED_CODES.has(mapped.code)) {
        setSessionExpired(true);
      }
      if (mapped.code && TRANSIENT_ERROR_CODES.has(mapped.code)) {
        scheduleRetry();
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const onDisconnect = async () => {
    if (!session?.session_id) {
      setStatus("No active VNC session to disconnect.");
      setConnectionState("disconnected");
      return;
    }

    setIsDisconnecting(true);
    setStatus("Disconnecting VNC session...");
    setConnectionState("connecting");
    try {
      rfbRef.current?.disconnect();
      rfbRef.current = null;
      await deleteVncSession(session.session_id);
      setSession(null);
      setConnectionState("disconnected");
      setTimeoutWarningSeconds(null);
      setStatus("VNC session disconnected.");
      resetFailureUi();
    } catch (error) {
      setConnectionState("failed");
      const mapped = classifyError(error);
      setLastErrorCode(mapped.code);
      setStatus(mapped.message);
      if (mapped.code && SESSION_EXPIRED_CODES.has(mapped.code)) {
        setSessionExpired(true);
      }
    } finally {
      setIsDisconnecting(false);
    }
  };

  const onFullscreen = async () => {
    if (!viewerRef.current) return;
    try {
      if (document.fullscreenElement) {
        await document.exitFullscreen();
      } else {
        await viewerRef.current.requestFullscreen();
      }
    } catch {
      setStatus("Fullscreen mode is unavailable in this browser.");
    }
  };

  const onCtrlAltDel = () => {
    if (!rfbRef.current) {
      setStatus("Connect a viewer session first to send Ctrl+Alt+Del.");
      return;
    }
    try {
      rfbRef.current.sendCtrlAltDel();
      setStatus("Sent Ctrl+Alt+Del to remote session.");
    } catch {
      setStatus("Unable to send Ctrl+Alt+Del to remote session.");
    }
  };

  const onReadLocalClipboard = async () => {
    if (!capabilities.clipboard) {
      setClipboardStatus("Clipboard is disabled by server capability for this target.");
      logClipboardTelemetry("read_local", "failure", "capability_disabled");
      return;
    }
    if (!navigator.clipboard?.readText) {
      setClipboardPermission("unsupported");
      setClipboardStatus("Clipboard read is not supported by this browser.");
      logClipboardTelemetry("read_local", "failure", "browser_unsupported");
      return;
    }

    setIsReadingClipboard(true);
    try {
      const text = await navigator.clipboard.readText();
      setClipboardPermission("granted");
      setClipboardText(text);
      setClipboardStatus("Loaded local clipboard text into the panel.");
      logClipboardTelemetry("read_local", "success", "ok");
    } catch {
      setClipboardPermission("denied");
      setClipboardStatus("Clipboard permission denied. Allow access and retry.");
      logClipboardTelemetry("read_local", "failure", "permission_denied");
    } finally {
      setIsReadingClipboard(false);
    }
  };

  const onSendClipboardToRemote = async () => {
    if (!capabilities.clipboard) {
      setClipboardStatus("Clipboard is disabled by server capability for this target.");
      logClipboardTelemetry("send_remote", "failure", "capability_disabled");
      return;
    }
    if (!rfbRef.current?.clipboardPasteFrom) {
      setClipboardStatus("Remote clipboard send is not supported by the active viewer.");
      logClipboardTelemetry("send_remote", "failure", "viewer_unsupported");
      return;
    }

    const payload = clipboardText.trimEnd();
    if (!payload) {
      setClipboardStatus("Enter clipboard text before sending.");
      logClipboardTelemetry("send_remote", "failure", "empty_payload");
      return;
    }
    if (payload.length > MAX_CLIPBOARD_CHARS) {
      setClipboardStatus(`Clipboard payload exceeds ${MAX_CLIPBOARD_CHARS.toLocaleString()} character limit.`);
      logClipboardTelemetry("send_remote", "failure", "payload_too_large");
      return;
    }

    setIsSendingClipboard(true);
    try {
      rfbRef.current.clipboardPasteFrom(payload);
      setClipboardStatus("Clipboard text sent to remote session.");
      logClipboardTelemetry("send_remote", "success", `length_${payload.length}`);
    } catch {
      setClipboardStatus("Failed to send clipboard text to remote session.");
      logClipboardTelemetry("send_remote", "failure", "runtime_error");
    } finally {
      setIsSendingClipboard(false);
    }
  };

  const onCopyRemoteClipboardToLocal = async () => {
    if (!remoteClipboardText) {
      setClipboardStatus("No remote clipboard text available yet.");
      logClipboardTelemetry("copy_remote_local", "failure", "empty_remote");
      return;
    }
    if (!navigator.clipboard?.writeText) {
      setClipboardPermission("unsupported");
      setClipboardStatus("Clipboard write is not supported by this browser.");
      logClipboardTelemetry("copy_remote_local", "failure", "browser_unsupported");
      return;
    }
    try {
      await navigator.clipboard.writeText(remoteClipboardText);
      setClipboardPermission("granted");
      setClipboardStatus("Copied remote clipboard text to local clipboard.");
      logClipboardTelemetry("copy_remote_local", "success", "ok");
    } catch {
      setClipboardPermission("denied");
      setClipboardStatus("Clipboard permission denied while writing locally.");
      logClipboardTelemetry("copy_remote_local", "failure", "permission_denied");
    }
  };

  const startUpload = React.useCallback((item: TransferItem) => {
    if (connectionState !== "connected") {
      setTransferItems((prev) => prev.map((entry) => entry.id === item.id
        ? { ...entry, state: "failure", progress: 0, error: "Connect the VNC session before transferring files." }
        : entry));
      setTransferStatus("Upload failed: connect the session first.");
      return;
    }
    if (item.size > MAX_TRANSFER_FILE_BYTES) {
      const maxMb = Math.round(MAX_TRANSFER_FILE_BYTES / (1024 * 1024));
      setTransferItems((prev) => prev.map((entry) => entry.id === item.id
        ? { ...entry, state: "failure", progress: 0, error: `File exceeds ${maxMb} MB transfer limit.` }
        : entry));
      setTransferStatus(`Upload failed for ${item.name}: file exceeds ${maxMb} MB limit.`);
      return;
    }

    setTransferItems((prev) => prev.map((entry) => entry.id === item.id
      ? { ...entry, state: "uploading", progress: 25, error: undefined }
      : entry));

    window.setTimeout(() => {
      setTransferItems((prev) => prev.map((entry) => entry.id === item.id
        ? { ...entry, state: "success", progress: 100, error: undefined }
        : entry));
      setTransferStatus(`Uploaded ${item.name}.`);
    }, 350);
  }, [connectionState]);

  const queueFiles = React.useCallback((incoming: File[]) => {
    if (!capabilities.file_transfer) {
      setTransferStatus("File transfer is disabled by server capability for this target.");
      return;
    }
    if (incoming.length === 0) {
      return;
    }

    const queued = incoming.map((file) => ({
      id: `${Date.now()}-${file.name}-${Math.random().toString(36).slice(2, 8)}`,
      name: file.name,
      size: file.size,
      state: "queued" as const,
      progress: 0,
    }));

    setTransferItems((prev) => [...queued, ...prev]);
    setTransferStatus(`Queued ${incoming.length} file${incoming.length > 1 ? "s" : ""} for transfer.`);

    window.setTimeout(() => {
      for (const item of queued) {
        startUpload(item);
      }
    }, 0);
  }, [capabilities.file_transfer, startUpload]);

  const onSelectTransferFiles = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.target.files ?? []);
    queueFiles(files);
    event.target.value = "";
  };

  const onDropTransferFiles = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    if (!capabilities.drag_drop_upload) {
      setTransferStatus("Drag-and-drop upload is disabled for this session.");
      setIsDragActive(false);
      return;
    }
    setIsDragActive(false);
    const files = Array.from(event.dataTransfer.files ?? []);
    queueFiles(files);
  };

  const onRetryTransfer = (itemId: string) => {
    const item = transferItems.find((entry) => entry.id === itemId);
    if (!item) return;
    startUpload(item);
  };

  const onRequestFallbackTransfer = async () => {
    if (!session?.session_id) {
      setFallbackStatus("Start a VNC session before requesting fallback transfer.");
      return;
    }
    setIsLoadingFallback(true);
    setFallbackStatus("Requesting fallback transfer method...");
    try {
      const fallback = await getVncTransferFallback(session.session_id);
      setFallbackTransfer(fallback);
      setFallbackStatus(`Using fallback transfer method: ${fallback.label}.`);
    } catch (error) {
      const mapped = classifyError(error);
      setFallbackStatus(mapped.message);
    } finally {
      setIsLoadingFallback(false);
    }
  };

  const onRedirectToLogin = () => {
    navigate("/login", { replace: true });
  };


  React.useEffect(() => {
    if (!session || connectionState !== "connected") {
      setTimeoutWarningSeconds(null);
      return;
    }

    const policy = session.timeout_policy ?? DEFAULT_TIMEOUT_POLICY;
    const warningSeconds = Math.max(5, Number(policy.warning_seconds || 60));
    const createdAtMs = Number(session.created_at) * 1000;

    const interval = window.setInterval(() => {
      const now = Date.now();
      const idleDeadline = lastActivityAtRef.current + Number(policy.idle_timeout_seconds) * 1000;
      const maxDeadline = createdAtMs + Number(policy.max_session_duration_seconds) * 1000;
      const effectiveDeadline = Math.min(idleDeadline, maxDeadline);
      const remainingMs = effectiveDeadline - now;

      if (remainingMs <= 0 && !policyTimeoutHandledRef.current) {
        policyTimeoutHandledRef.current = true;
        setTimeoutWarningSeconds(null);
        setSessionExpired(true);
        setConnectionState("failed");
        setLastErrorCode("VNC_SESSION_TERMINATED");
        setStatus("Session terminated due to idle timeout or max duration policy.");
        try {
          rfbRef.current?.disconnect();
        } catch {
          // no-op
        }
        if (session.session_id) {
          void deleteVncSession(session.session_id);
        }
        return;
      }

      if (remainingMs <= warningSeconds * 1000) {
        setTimeoutWarningSeconds(Math.max(0, Math.ceil(remainingMs / 1000)));
      } else {
        setTimeoutWarningSeconds(null);
      }
    }, 1000);

    return () => window.clearInterval(interval);
  }, [connectionState, session, setSessionExpired]);

  React.useEffect(() => {
    if (connectionState !== "connected") return;

    const onActivity = () => {
      const now = Date.now();
      if (now - lastActivityAtRef.current >= ACTIVITY_HEARTBEAT_MS) {
        lastActivityAtRef.current = now;
      }
    };

    window.addEventListener("mousemove", onActivity);
    window.addEventListener("keydown", onActivity);
    return () => {
      window.removeEventListener("mousemove", onActivity);
      window.removeEventListener("keydown", onActivity);
    };
  }, [connectionState]);

  React.useEffect(() => {
    if (!nextRetryAt) return;
    const delay = Math.max(0, nextRetryAt - Date.now());
    const timeout = window.setTimeout(() => {
      setRetryClock(Date.now());
    }, delay + 25);
    return () => window.clearTimeout(timeout);
  }, [nextRetryAt]);

  React.useEffect(() => {
    if (!sessionExpired) return;
    const timeout = window.setTimeout(() => {
      navigate("/login", { replace: true });
    }, 2500);
    return () => window.clearTimeout(timeout);
  }, [navigate, sessionExpired]);

  React.useEffect(() => {
    return () => {
      try {
        rfbRef.current?.disconnect();
      } catch {
        // no-op
      }
      rfbRef.current = null;
    };
  }, []);

  const retryBlocked = Boolean(nextRetryAt && retryClock < nextRetryAt);
  const canReconnect = connectionState === "failed" && !!lastErrorCode && (TRANSIENT_ERROR_CODES.has(lastErrorCode) || SESSION_EXPIRED_CODES.has(lastErrorCode));

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Remote Desktop"
        description="Create brokered noVNC sessions with target validation, connection controls, and live state."
      />

      {sessionExpired && (
        <Card className="border-amber-300 bg-amber-50">
          <CardContent className="flex flex-col gap-3 py-4 text-sm md:flex-row md:items-center md:justify-between">
            <p data-testid="vnc-expiry-banner">Session expired or terminated. Re-authentication is required; redirecting to login.</p>
            <Button size="sm" variant="outline" onClick={onRedirectToLogin}>Go to Login</Button>
          </CardContent>
        </Card>
      )}

      {timeoutWarningSeconds !== null && timeoutWarningSeconds > 0 && (
        <Card className="border-orange-300 bg-orange-50" data-testid="vnc-timeout-warning">
          <CardContent className="py-3 text-sm text-orange-900">
            Your session will be terminated in {timeoutWarningSeconds}s due to inactivity or max duration policy. Move the mouse or press a key to keep the session active.
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <MonitorSmartphone className="h-5 w-5" />
            noVNC Connection Form
          </CardTitle>
          <CardDescription>
            Target ID is required. Host/port, label, and auth mode are retained locally for convenience.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={onSubmit} className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="vnc-target-id">Target ID</Label>
                <Input
                  id="vnc-target-id"
                  value={form.targetId}
                  onChange={(e) => setField("targetId", e.target.value)}
                  placeholder="demo"
                  aria-invalid={Boolean(errors.targetId)}
                />
                {errors.targetId && <p className="text-xs text-destructive">{errors.targetId}</p>}
              </div>

              <div className="space-y-2">
                <Label htmlFor="vnc-display-label">Display label (optional)</Label>
                <Input
                  id="vnc-display-label"
                  value={form.displayLabel}
                  onChange={(e) => setField("displayLabel", e.target.value)}
                  placeholder="Prod support desktop"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="vnc-host">Host (optional)</Label>
                <Input
                  id="vnc-host"
                  value={form.host}
                  onChange={(e) => setField("host", e.target.value)}
                  placeholder="vnc-host.internal"
                  aria-invalid={Boolean(errors.host)}
                />
                {errors.host && <p className="text-xs text-destructive">{errors.host}</p>}
              </div>

              <div className="space-y-2">
                <Label htmlFor="vnc-port">Port (optional)</Label>
                <Input
                  id="vnc-port"
                  value={form.port}
                  onChange={(e) => setField("port", e.target.value)}
                  placeholder="5900"
                  aria-invalid={Boolean(errors.port)}
                />
                {errors.port && <p className="text-xs text-destructive">{errors.port}</p>}
              </div>

              <div className="space-y-2 md:col-span-2">
                <Label htmlFor="vnc-auth-mode">Auth input mode</Label>
                <Select value={form.authMode} onValueChange={(value) => setField("authMode", value as AuthInputMode)}>
                  <SelectTrigger id="vnc-auth-mode" className="w-full md:w-[280px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="session_token">Session token (recommended)</SelectItem>
                    <SelectItem value="password">Password (do not persist secret)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Button type="submit" disabled={isSubmitting}>
                {isSubmitting ? "Starting..." : "Connect Viewer"}
              </Button>
              <Button type="button" variant="outline" disabled={isDisconnecting} onClick={onDisconnect}>
                <Unplug className="mr-1 h-4 w-4" />
                {isDisconnecting ? "Disconnecting..." : "Disconnect"}
              </Button>
              <Button type="button" variant="outline" onClick={onFullscreen}>
                <Expand className="mr-1 h-4 w-4" />
                Fullscreen
              </Button>
              <Button type="button" variant="outline" onClick={onCtrlAltDel}>
                <Power className="mr-1 h-4 w-4" />
                Ctrl+Alt+Del
              </Button>
              <Badge variant={statusVariant(connectionState)} data-testid="connection-state-badge">
                {connectionState}
              </Badge>
            </div>

            {canReconnect && (
              <div className="flex items-center gap-2 text-sm" data-testid="vnc-reconnect-cta">
                <Button type="button" variant="secondary" onClick={onReconnect} disabled={retryBlocked || isSubmitting}>
                  <RotateCcw className="mr-1 h-4 w-4" />
                  Retry / Reconnect
                </Button>
                {retryBlocked && (
                  <span className="text-muted-foreground">Retry available soon (backoff policy active).</span>
                )}
              </div>
            )}

            {status && (
              <p className="text-sm text-muted-foreground" data-testid="vnc-form-status">
                {status}
              </p>
            )}
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Viewer</CardTitle>
          <CardDescription>Remote session rendering surface for noVNC.</CardDescription>
        </CardHeader>
        <CardContent>
          <div
            ref={viewerRef}
            data-testid="vnc-viewer-container"
            className="min-h-[360px] w-full rounded-md border border-border bg-black/90"
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Clipboard</CardTitle>
          <CardDescription>
            Explicit clipboard actions are enabled only when both browser permissions and server capability allow it.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="vnc-clipboard-input">Clipboard text</Label>
              <Textarea
                id="vnc-clipboard-input"
                data-testid="vnc-clipboard-input"
                value={clipboardText}
                onChange={(e) => setClipboardText(e.target.value)}
                placeholder="Paste or read local clipboard text here"
                rows={6}
              />
              <p className="text-xs text-muted-foreground">{clipboardText.length} / {MAX_CLIPBOARD_CHARS.toLocaleString()} chars</p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="vnc-remote-clipboard">Remote clipboard snapshot</Label>
              <Textarea
                id="vnc-remote-clipboard"
                data-testid="vnc-remote-clipboard"
                value={remoteClipboardText}
                readOnly
                rows={6}
                placeholder="Remote clipboard updates will appear here"
              />
            </div>
          </div>

          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" onClick={onReadLocalClipboard} disabled={isReadingClipboard}>
              {isReadingClipboard ? "Reading..." : "Read Local Clipboard"}
            </Button>
            <Button type="button" variant="outline" onClick={onSendClipboardToRemote} disabled={isSendingClipboard || connectionState !== "connected"}>
              {isSendingClipboard ? "Sending..." : "Send to Remote"}
            </Button>
            <Button type="button" variant="outline" onClick={onCopyRemoteClipboardToLocal}>
              Copy Remote to Local
            </Button>
          </div>

          <p className="text-xs text-muted-foreground" data-testid="vnc-clipboard-capability">
            clipboard_supported={String(capabilities.clipboard)} browser_permission={clipboardPermission}
          </p>
          {clipboardStatus && (
            <p className="text-sm text-muted-foreground" data-testid="vnc-clipboard-status">{clipboardStatus}</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>File Transfer</CardTitle>
          <CardDescription>
            Upload is available only when the session capability enables file transfer. Drag/drop requires drag-drop capability.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {!capabilities.file_transfer ? (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground" data-testid="vnc-transfer-unsupported">
                File transfer is not available for this target. Use fallback transfer instead.
              </p>
              <Button type="button" variant="outline" onClick={onRequestFallbackTransfer} disabled={isLoadingFallback}>
                {isLoadingFallback ? "Loading fallback..." : "Get Fallback Transfer Method"}
              </Button>
              {fallbackTransfer && (
                <div className="rounded-md border p-3 text-sm" data-testid="vnc-fallback-transfer-panel">
                  <p><span className="font-medium">Method:</span> {fallbackTransfer.label} ({fallbackTransfer.method})</p>
                  <p><span className="font-medium">Instructions:</span> {fallbackTransfer.instructions}</p>
                  <p><span className="font-medium">Endpoint:</span> <code className="break-all">{fallbackTransfer.url}</code></p>
                  <p><span className="font-medium">Expires:</span> {new Date(fallbackTransfer.expires_at * 1000).toLocaleString()}</p>
                </div>
              )}
              {fallbackStatus && (
                <p className="text-sm text-muted-foreground" data-testid="vnc-fallback-status">{fallbackStatus}</p>
              )}
            </div>
          ) : (
            <>
              <div className="flex flex-wrap gap-2">
                <Button type="button" variant="outline" onClick={() => fileInputRef.current?.click()}>
                  Upload Files
                </Button>
                <input
                  ref={fileInputRef}
                  type="file"
                  multiple
                  className="hidden"
                  data-testid="vnc-transfer-input"
                  onChange={onSelectTransferFiles}
                />
              </div>

              <div
                data-testid="vnc-drag-drop-zone"
                className={`rounded-md border border-dashed p-4 text-sm ${isDragActive ? "border-primary bg-primary/5" : "border-border"} ${!capabilities.drag_drop_upload ? "opacity-60" : ""}`}
                onDragOver={(event) => {
                  event.preventDefault();
                  if (capabilities.drag_drop_upload) {
                    setIsDragActive(true);
                  }
                }}
                onDragLeave={() => setIsDragActive(false)}
                onDrop={onDropTransferFiles}
              >
                {capabilities.drag_drop_upload
                  ? "Drag and drop files here to queue upload."
                  : "Drag and drop upload is disabled for this session."}
              </div>

              {transferItems.length > 0 && (
                <ul className="space-y-2" data-testid="vnc-transfer-list">
                  {transferItems.map((item) => (
                    <li key={item.id} className="rounded border p-2 text-sm">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-medium">{item.name}</span>
                        <span className="text-xs text-muted-foreground">{item.state} ({item.progress}%)</span>
                      </div>
                      {item.error && <p className="text-xs text-destructive">{item.error}</p>}
                      {item.state === "failure" && (
                        <Button type="button" size="sm" variant="secondary" onClick={() => onRetryTransfer(item.id)} className="mt-2">
                          Retry Upload
                        </Button>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}

          {transferStatus && (
            <p className="text-sm text-muted-foreground" data-testid="vnc-transfer-status">{transferStatus}</p>
          )}
        </CardContent>
      </Card>

      {session && (
        <Card>
          <CardHeader>
            <CardTitle>Session Summary</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p><span className="font-medium">Session ID:</span> <code>{session.session_id}</code></p>
            <p><span className="font-medium">WebSocket URL:</span> <code className="break-all">{session.ws_url}</code></p>
            <p><span className="font-medium">Expires at:</span> {new Date(session.expires_at * 1000).toLocaleString()}</p>
            <p><span className="font-medium">Idle timeout:</span> {(session.timeout_policy?.idle_timeout_seconds ?? DEFAULT_TIMEOUT_POLICY.idle_timeout_seconds)}s</p>
            <p><span className="font-medium">Max duration:</span> {(session.timeout_policy?.max_session_duration_seconds ?? DEFAULT_TIMEOUT_POLICY.max_session_duration_seconds)}s</p>
            <p>
              <span className="font-medium">Capabilities:</span>{" "}
              clipboard={String(capabilities.clipboard)} file_transfer={String(capabilities.file_transfer)}{" "}
              drag_drop_upload={String(capabilities.drag_drop_upload)}
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
