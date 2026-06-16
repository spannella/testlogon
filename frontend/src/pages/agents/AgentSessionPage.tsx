import * as React from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Bot, Unplug, Square, RotateCcw, Send } from "lucide-react";
import "@xterm/xterm/css/xterm.css";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { listWorkers } from "@/api/endpoints/agentWorkers";
import { createAgentSession } from "@/api/endpoints/agentSessions";
import type { AgentSessionState, Worker } from "@/api/types";

// ── State badge styling ──────────────────────────────────────────

type ConnPhase = "idle" | "connecting" | "connected" | "ended" | "failed";

const SESSION_BADGE: Record<
  AgentSessionState,
  { variant: "secondary" | "default" | "destructive" | "outline"; label: string }
> = {
  starting: { variant: "secondary", label: "starting" },
  ready: { variant: "default", label: "ready" },
  awaiting_input: { variant: "destructive", label: "awaiting input" },
  running: { variant: "default", label: "running" },
  ended: { variant: "outline", label: "ended" },
  error: { variant: "destructive", label: "error" },
};

// ── xterm loader (mirrors BrowserSshPage; uses global stubs in tests) ──

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

type TerminalInstance = ReturnType<NonNullable<typeof window.Terminal>> | null;

async function loadXterm(): Promise<{
  Terminal: NonNullable<typeof window.Terminal>;
  FitAddon: NonNullable<typeof window.FitAddon>["FitAddon"];
}> {
  if (window.Terminal && window.FitAddon) {
    return { Terminal: window.Terminal, FitAddon: window.FitAddon.FitAddon };
  }
  const [termMod, fitMod] = await Promise.all([
    import("@xterm/xterm"),
    import("@xterm/addon-fit"),
  ]);
  return {
    Terminal: termMod.Terminal as unknown as NonNullable<typeof window.Terminal>,
    FitAddon: fitMod.FitAddon as unknown as NonNullable<
      typeof window.FitAddon
    >["FitAddon"],
  };
}

export default function AgentSessionPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [workerId, setWorkerId] = React.useState<string>(
    () => searchParams.get("workerId") || "",
  );
  const [sessionId, setSessionId] = React.useState<string>("");
  const [phase, setPhase] = React.useState<ConnPhase>("idle");
  const [sessionState, setSessionState] =
    React.useState<AgentSessionState | null>(null);
  const [status, setStatus] = React.useState<string>("");
  const [busy, setBusy] = React.useState(false);
  // Feedback prompt surfaced from a [AGENT_FEEDBACK_NEEDED]-style signal.
  const [feedback, setFeedback] = React.useState<{
    requestId: string;
    question: string;
  } | null>(null);
  const [feedbackAnswer, setFeedbackAnswer] = React.useState("");

  const termRef = React.useRef<HTMLDivElement | null>(null);
  const xtermRef = React.useRef<TerminalInstance>(null);
  const wsRef = React.useRef<WebSocket | null>(null);
  const fitRef = React.useRef<{ fit(): void } | null>(null);
  // True when WE initiated a Stop (so onclose doesn't show a "dropped" message).
  const stoppedRef = React.useRef(false);

  // Only ready/running workers can host an interactive session.
  const { data: workersData } = useQuery({
    queryKey: ["agent-workers", "list", "sessionable"],
    queryFn: () => listWorkers(),
    staleTime: 15_000,
  });
  const sessionableWorkers: Worker[] = (workersData?.workers ?? []).filter(
    (w) => w.worker_status === "ready" || w.worker_status === "running",
  );

  const teardownTerminal = React.useCallback(() => {
    wsRef.current?.close();
    wsRef.current = null;
    xtermRef.current?.dispose();
    xtermRef.current = null;
    fitRef.current = null;
  }, []);

  // Detach (NOT stop) on unmount/tab close: closing the WS leaves the server
  // session + PTY alive (ACS-006) so we can reattach with the session_id.
  React.useEffect(() => () => teardownTerminal(), [teardownTerminal]);

  const openTerminal = React.useCallback(
    async (reattachSessionId?: string) => {
      if (!workerId) {
        setStatus("Select a worker first.");
        return;
      }
      setBusy(true);
      setPhase("connecting");
      setFeedback(null);
      stoppedRef.current = false;
      setStatus("Loading terminal engine…");

      try {
        // For a fresh start we mint a session record via REST so the badge has
        // a session_id immediately; a reattach reuses the existing one.
        let sid = reattachSessionId || "";
        if (!sid) {
          setStatus("Creating session…");
          const sess = await createAgentSession(workerId, { cols: 120, rows: 24 });
          sid = sess.session_id;
          setSessionState(sess.state);
        }
        setSessionId(sid);
        // Persist for reconnect after a reload.
        setSearchParams(
          (prev) => {
            const next = new URLSearchParams(prev);
            next.set("workerId", workerId);
            next.set("sessionId", sid);
            return next;
          },
          { replace: true },
        );

        const { Terminal, FitAddon } = await loadXterm();
        if (!termRef.current) throw new Error("Terminal container unavailable.");

        teardownTerminal();
        const xterm = new Terminal({
          cursorBlink: true,
          fontSize: 14,
          fontFamily: '"JetBrains Mono", monospace',
          theme: {
            background: "#0f172a",
            foreground: "#e2e8f0",
            cursor: "#94a3b8",
          },
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

        setStatus("Connecting to Claude session…");
        const proto = window.location.protocol === "https:" ? "wss" : "ws";
        const wsUrl = `${proto}://${window.location.host}/api/agent-session/ws`;
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          ws.send(
            JSON.stringify({
              type: "connect",
              payload: {
                worker_id: workerId,
                ...(sid ? { session_id: sid } : {}),
                cols: 120,
                rows: 24,
              },
            }),
          );
        };

        ws.onmessage = (ev) => {
          try {
            const msg = JSON.parse(ev.data as string) as {
              type: string;
              payload: Record<string, unknown>;
            };
            if (msg.type === "status") {
              const ph = msg.payload.phase as string;
              const st = msg.payload.state as AgentSessionState | undefined;
              if (st) setSessionState(st);
              if (msg.payload.session_id)
                setSessionId(msg.payload.session_id as string);
              if (ph === "connected") {
                setPhase("connected");
                setStatus("Connected.");
                ws.send(
                  JSON.stringify({ type: "resize", payload: { cols: 120, rows: 24 } }),
                );
              } else if (ph === "ended") {
                setPhase("ended");
                setSessionState("ended");
                setStatus("Session ended.");
              } else {
                setStatus((msg.payload.message as string) || ph);
              }
            } else if (msg.type === "output") {
              xterm.write((msg.payload.data as string) || "");
            } else if (msg.type === "feedback_request") {
              setSessionState("awaiting_input");
              setFeedback({
                requestId: (msg.payload.request_id as string) || "",
                question:
                  (msg.payload.question as string) ||
                  "The agent is waiting for your input.",
              });
            } else if (msg.type === "agent_complete") {
              setSessionState("ended");
              setStatus("Agent reported completion.");
            } else if (msg.type === "agent_error") {
              setSessionState("error");
              setStatus(`Agent error: ${(msg.payload.match as string) || ""}`);
            } else if (msg.type === "error") {
              const code = msg.payload.code as string;
              const errMsg = (msg.payload.message as string) || code;
              setPhase("failed");
              setStatus(`Error: ${errMsg}`);
              xterm.writeln(`\r\n\x1b[31mSession error: ${errMsg}\x1b[0m`);
            }
          } catch {
            /* ignore malformed messages */
          }
        };

        ws.onerror = () => {
          setPhase("failed");
          setStatus(
            "WebSocket error — check that agent sessions are enabled on the server.",
          );
        };

        ws.onclose = () => {
          if (stoppedRef.current) return;
          if (phase !== "failed") {
            setPhase("idle");
            setStatus("Detached — the session is still running. Reconnect to resume.");
          }
        };

        // Forward keystrokes to the live Claude PTY.
        xterm.onData((data) => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: "input", payload: { data } }));
            // Typing clears the awaiting-input affordance optimistically.
            if (feedback) setFeedback(null);
          }
        });
      } catch (err) {
        setPhase("failed");
        setStatus(err instanceof Error ? err.message : "Unexpected error.");
      } finally {
        setBusy(false);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [workerId, teardownTerminal, setSearchParams],
  );

  // Auto-reconnect to a session_id present in the URL (e.g. after reload).
  React.useEffect(() => {
    const qsSession = searchParams.get("sessionId");
    if (qsSession && workerId && phase === "idle" && !sessionId) {
      void openTerminal(qsSession);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const sendFeedback = () => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const data = feedbackAnswer.endsWith("\n")
      ? feedbackAnswer
      : `${feedbackAnswer}\n`;
    ws.send(JSON.stringify({ type: "input", payload: { data } }));
    setFeedbackAnswer("");
    setFeedback(null);
    setSessionState("running");
  };

  const stopSession = () => {
    const ws = wsRef.current;
    stoppedRef.current = true;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "stop", payload: {} }));
    }
    setPhase("ended");
    setSessionState("ended");
    setStatus("Session stopped.");
  };

  const reconnect = () => {
    if (sessionId) void openTerminal(sessionId);
  };

  const detach = () => {
    teardownTerminal();
    setPhase("idle");
    setStatus("Detached — the session is still running. Reconnect to resume.");
  };

  // Keep the terminal fitted to its container.
  React.useEffect(() => {
    if (!fitRef.current) return;
    const observer = new ResizeObserver(() => fitRef.current?.fit());
    if (termRef.current) observer.observe(termRef.current);
    return () => observer.disconnect();
  }, [phase]);

  const badge = sessionState ? SESSION_BADGE[sessionState] : null;

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Claude Code Session"
        description="Drive a live, interactive Claude Code agent on one of your workers. No host, port, or key — just pick a worker and open a session."
      />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bot className="h-5 w-5" />
            Agent Session
            {badge && (
              <Badge variant={badge.variant} className="ml-2">
                {badge.label}
              </Badge>
            )}
          </CardTitle>
          <CardDescription>
            Sessions survive closing this tab — reconnect to resume with the
            recent output replayed.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="acs-worker">Worker</Label>
              <Select
                value={workerId}
                onValueChange={setWorkerId}
                disabled={phase === "connected" || busy}
              >
                <SelectTrigger id="acs-worker">
                  <SelectValue placeholder="Select a ready worker" />
                </SelectTrigger>
                <SelectContent>
                  {sessionableWorkers.length === 0 ? (
                    <SelectItem value="__none" disabled>
                      No ready/running workers
                    </SelectItem>
                  ) : (
                    sessionableWorkers.map((w) => (
                      <SelectItem key={w.worker_id} value={w.worker_id}>
                        {w.label} ({w.worker_status})
                      </SelectItem>
                    ))
                  )}
                </SelectContent>
              </Select>
            </div>
            {sessionId && (
              <div className="space-y-2">
                <Label>Session</Label>
                <div className="truncate rounded-md border border-border bg-muted/40 px-3 py-2 text-xs font-mono text-muted-foreground">
                  {sessionId}
                </div>
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button
              onClick={() => openTerminal()}
              disabled={!workerId || busy || phase === "connected"}
            >
              <Bot className="mr-1 h-4 w-4" />
              {busy ? "Opening…" : "Open Claude Session"}
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={reconnect}
              disabled={!sessionId || phase === "connected" || phase === "ended"}
            >
              <RotateCcw className="mr-1 h-4 w-4" />
              Reconnect
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={detach}
              disabled={phase !== "connected"}
            >
              <Unplug className="mr-1 h-4 w-4" />
              Detach
            </Button>
            <Button
              type="button"
              variant="destructive"
              onClick={stopSession}
              disabled={!sessionId || phase === "ended"}
            >
              <Square className="mr-1 h-4 w-4" />
              Stop
            </Button>
            {status && (
              <span className="text-sm text-muted-foreground">{status}</span>
            )}
          </div>
        </CardContent>
      </Card>

      {feedback && (
        <Card className="border-amber-500/60">
          <CardHeader>
            <CardTitle className="text-base">Agent is awaiting your input</CardTitle>
            <CardDescription>{feedback.question}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <Input
                autoFocus
                value={feedbackAnswer}
                placeholder="Type your response…"
                onChange={(e) => setFeedbackAnswer(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") sendFeedback();
                }}
              />
              <Button onClick={sendFeedback} disabled={!feedbackAnswer.trim()}>
                <Send className="mr-1 h-4 w-4" />
                Send
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Terminal</CardTitle>
          <CardDescription>
            Interactive Claude Code session — output rendered in-browser,
            keystrokes forwarded over the encrypted WebSocket.
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
