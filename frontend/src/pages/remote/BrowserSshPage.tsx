import * as React from "react";
import { useSearchParams } from "react-router-dom";
import { Terminal, Unplug, Key } from "lucide-react";
import "@xterm/xterm/css/xterm.css";
import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

type AuthType = "password" | "private_key";
type ConnectionState = "disconnected" | "connecting" | "connected" | "failed";

const STORAGE_KEY = "browser_ssh_form_v1";

type FormValues = {
  host: string;
  port: string;
  username: string;
  authType: AuthType;
};

function loadForm(): FormValues {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { host: "", port: "22", username: "", authType: "password" };
    const p = JSON.parse(raw) as Partial<FormValues>;
    return {
      host: p.host ?? "",
      port: p.port ?? "22",
      username: p.username ?? "",
      authType: p.authType === "private_key" ? "private_key" : "password",
    };
  } catch {
    return { host: "", port: "22", username: "", authType: "password" };
  }
}

function persistForm(values: FormValues): void {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(values)); } catch { /* ignore */ }
}

const STATUS_VARIANTS: Record<ConnectionState, "secondary" | "default" | "destructive"> = {
  disconnected: "secondary",
  connecting: "secondary",
  connected: "default",
  failed: "destructive",
};

declare global {
  interface Window {
    Terminal?: new (options?: Record<string, unknown>) => {
      loadAddon(addon: unknown): void;
      open(el: Element): void;
      focus(): void;
      onData(cb: (data: string) => void): void;
      write(data: string): void;
      writeln(data: string): void;
      dispose(): void;
    };
    FitAddon?: { FitAddon: new () => { fit(): void } };
  }
}

type TerminalInstance = InstanceType<NonNullable<typeof window.Terminal>> | null;

async function loadXterm(): Promise<{ Terminal: NonNullable<typeof window.Terminal>; FitAddon: NonNullable<typeof window.FitAddon>["FitAddon"] }> {
  // Use globally injected stubs in tests.
  if (window.Terminal && window.FitAddon) {
    return { Terminal: window.Terminal, FitAddon: window.FitAddon.FitAddon };
  }
  // Lazy-load from local packages (CSS is imported statically above — no CDN).
  const [termMod, fitMod] = await Promise.all([
    import("@xterm/xterm"),
    import("@xterm/addon-fit"),
  ]);
  return { Terminal: termMod.Terminal as unknown as NonNullable<typeof window.Terminal>, FitAddon: fitMod.FitAddon as unknown as NonNullable<typeof window.FitAddon>["FitAddon"] };
}

export default function BrowserSshPage() {
  const [searchParams] = useSearchParams();
  // Deep-link support (CTI-006): /remote/ssh?host=&port=&username=&host_id=
  // pre-fills the form so quick-connect from host inventory / "Open terminal"
  // on a compute instance lands on a ready-to-connect terminal.
  const hostIdRef = React.useRef<string>(searchParams.get("host_id") || "");
  const [form, setForm] = React.useState<FormValues>(() => {
    const base = loadForm();
    const qHost = searchParams.get("host");
    if (!qHost) return base;
    return {
      host: qHost,
      port: searchParams.get("port") || base.port || "22",
      username: searchParams.get("username") || base.username || "",
      authType: base.authType,
    };
  });
  const [password, setPassword] = React.useState("");
  const [privateKey, setPrivateKey] = React.useState("");
  const [status, setStatus] = React.useState("");
  const [connectionState, setConnectionState] = React.useState<ConnectionState>("disconnected");
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const [formCollapsed, setFormCollapsed] = React.useState(false);

  const termRef = React.useRef<HTMLDivElement | null>(null);
  const xtermRef = React.useRef<TerminalInstance>(null);
  const wsRef = React.useRef<WebSocket | null>(null);
  const fitRef = React.useRef<{ fit(): void } | null>(null);

  const setField = <K extends keyof FormValues>(key: K, value: FormValues[K]) => {
    setForm((prev) => {
      const next = { ...prev, [key]: value };
      persistForm(next);
      return next;
    });
  };

  const disconnect = React.useCallback(() => {
    wsRef.current?.close();
    wsRef.current = null;
    xtermRef.current?.dispose();
    xtermRef.current = null;
    setConnectionState("disconnected");
    setStatus("Disconnected.");
  }, []);

  React.useEffect(() => () => disconnect(), [disconnect]);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.host.trim() || !form.username.trim()) {
      setStatus("Host and username are required.");
      return;
    }

    disconnect();
    setIsSubmitting(true);
    setConnectionState("connecting");
    setStatus("Loading terminal engine…");

    try {
      const { Terminal, FitAddon } = await loadXterm();

      if (!termRef.current) throw new Error("Terminal container unavailable.");

      const xterm = new Terminal({
        cursorBlink: true,
        fontSize: 14,
        fontFamily: "\"JetBrains Mono\", monospace",
        theme: { background: "#0f172a", foreground: "#e2e8f0", cursor: "#94a3b8" },
        rows: 24,
        cols: 120,
      });
      const fit = new FitAddon();
      xterm.loadAddon(fit);
      xterm.open(termRef.current);
      fit.fit();
      xterm.focus();
      xtermRef.current = xterm;
      fitRef.current = fit;

      setStatus("Connecting to SSH server…");

      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      const wsUrl = `${proto}://${window.location.host}/api/browser-ssh/ws`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        const connectMsg = {
          type: "connect",
          payload: {
            host: form.host.trim(),
            port: parseInt(form.port || "22", 10),
            username: form.username.trim(),
            authType: form.authType,
            ...(hostIdRef.current ? { host_id: hostIdRef.current } : {}),
            ...(form.authType === "password" ? { password } : { privateKey }),
          },
        };
        ws.send(JSON.stringify(connectMsg));
      };

      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data as string) as { type: string; payload: Record<string, unknown> };
          if (msg.type === "status") {
            const phase = msg.payload.phase as string;
            const message = msg.payload.message as string;
            if (phase === "connected") {
              setConnectionState("connected");
              setFormCollapsed(true);
              setStatus("Connected.");
              const cols = (msg.payload.cols as number) || 120;
              const rows = (msg.payload.rows as number) || 24;
              ws.send(JSON.stringify({ type: "resize", payload: { cols, rows } }));
            } else {
              setStatus(message || phase);
            }
          } else if (msg.type === "output") {
            xterm.write((msg.payload.data as string) || "");
          } else if (msg.type === "error") {
            const code = msg.payload.code as string;
            const errMsg = (msg.payload.message as string) || code;
            setConnectionState("failed");
            setStatus(`Error: ${errMsg}`);
            xterm.writeln(`\r\n\x1b[31mSSH error: ${errMsg}\x1b[0m`);
          }
        } catch { /* ignore malformed messages */ }
      };

      ws.onerror = () => {
        setConnectionState("failed");
        setStatus("WebSocket error — check that the SSH terminal is enabled on the server.");
        xtermRef.current?.writeln("\r\n\x1b[31mWebSocket connection failed.\x1b[0m");
      };

      ws.onclose = () => {
        if (connectionState !== "failed") {
          setConnectionState("disconnected");
          setStatus("Connection closed.");
        }
        xtermRef.current?.writeln("\r\n\x1b[33mSession closed.\x1b[0m");
      };

      // Forward keyboard input to SSH.
      xterm.onData((data) => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "input", payload: { data } }));
        }
      });
    } catch (err) {
      setConnectionState("failed");
      setStatus(err instanceof Error ? err.message : "Unexpected error.");
    } finally {
      setIsSubmitting(false);
    }
  };

  // Keep the terminal fitted to its container.
  React.useEffect(() => {
    if (!fitRef.current) return;
    const observer = new ResizeObserver(() => fitRef.current?.fit());
    if (termRef.current) observer.observe(termRef.current);
    return () => observer.disconnect();
  }, [connectionState]);

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Browser SSH Terminal"
        description="Secure in-browser SSH sessions — no local client required. Sessions are brokered via encrypted WebSocket."
      />

      <Card>
        <CardHeader
          className="cursor-pointer select-none"
          onClick={() => connectionState === "connected" && setFormCollapsed((v) => !v)}
        >
          <CardTitle className="flex items-center gap-2">
            <Terminal className="h-5 w-5" />
            SSH Connection
            {connectionState === "connected" && (
              <span className="ml-auto text-xs font-normal text-muted-foreground">
                {formCollapsed ? "▼ show" : "▲ hide"}
              </span>
            )}
          </CardTitle>
          {!formCollapsed && (
            <CardDescription>
              Connect to any SSH-accessible host. Credentials are never stored — they are transmitted once to open the session.
            </CardDescription>
          )}
        </CardHeader>
        {!formCollapsed && <CardContent>
          <form onSubmit={onSubmit} className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="ssh-host">Host</Label>
                <Input
                  id="ssh-host"
                  placeholder="data-node-01.internal"
                  value={form.host}
                  onChange={(e) => setField("host", e.target.value)}
                  autoComplete="off"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="ssh-port">Port</Label>
                <Input
                  id="ssh-port"
                  placeholder="22"
                  value={form.port}
                  onChange={(e) => setField("port", e.target.value)}
                  autoComplete="off"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="ssh-username">Username</Label>
                <Input
                  id="ssh-username"
                  placeholder="alice"
                  value={form.username}
                  onChange={(e) => setField("username", e.target.value)}
                  autoComplete="off"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="ssh-auth-type">Auth method</Label>
                <Select
                  value={form.authType}
                  onValueChange={(v) => setField("authType", v as AuthType)}
                >
                  <SelectTrigger id="ssh-auth-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="password">Password</SelectItem>
                    <SelectItem value="private_key">Private Key</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {form.authType === "password" ? (
                <div className="space-y-2 sm:col-span-2">
                  <Label htmlFor="ssh-password">Password</Label>
                  <Input
                    id="ssh-password"
                    type="password"
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="current-password"
                  />
                </div>
              ) : (
                <div className="space-y-2 sm:col-span-2">
                  <Label htmlFor="ssh-private-key">Private Key (PEM file)</Label>
                  <div className="flex items-center gap-3">
                    <Input
                      id="ssh-private-key"
                      type="file"
                      accept=".pem,.key,id_rsa,id_ed25519,id_ecdsa"
                      className="cursor-pointer"
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (!file) return;
                        const reader = new FileReader();
                        reader.onload = (ev) => setPrivateKey((ev.target?.result as string) ?? "");
                        reader.readAsText(file);
                      }}
                    />
                    {privateKey && (
                      <span className="shrink-0 text-sm text-muted-foreground">Key loaded ✓</span>
                    )}
                  </div>
                </div>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Button type="submit" disabled={isSubmitting || connectionState === "connected"}>
                {isSubmitting ? "Connecting…" : "Connect"}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={disconnect}
                disabled={connectionState === "disconnected"}
              >
                <Unplug className="mr-1 h-4 w-4" />
                Disconnect
              </Button>
              <Badge variant={STATUS_VARIANTS[connectionState]}>
                {connectionState}
              </Badge>
              {status && (
                <span className="text-sm text-muted-foreground">{status}</span>
              )}
            </div>
          </form>
        </CardContent>}
      </Card>

      {/* Terminal surface */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Key className="h-5 w-5" />
            Terminal
          </CardTitle>
          <CardDescription>
            Interactive xterm session. Output is rendered in-browser; keystrokes are forwarded over the encrypted WebSocket tunnel.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div
            ref={termRef}
            className="min-h-[360px] w-full overflow-hidden rounded-md border border-border bg-[#0f172a]"
            style={{ fontFamily: "'JetBrains Mono', monospace" }}
          />
        </CardContent>
      </Card>
    </div>
  );
}
