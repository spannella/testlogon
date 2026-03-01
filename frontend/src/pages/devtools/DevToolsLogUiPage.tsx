import { useEffect, useMemo, useState } from "react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  useDevtoolsBillingLedger,
  useDevtoolsBillingSummary,
  useDevtoolsEmailMessages,
  useDevtoolsSmsConversations,
} from "@/hooks/useDevtoolsData";
import { parseTotpConfigInput, type TotpConfig } from "@/lib/totpConfigParser";
import { generateTotpCode } from "@/lib/totpGenerator";

const ALL_INBOXES = "__all_inboxes__";

type EmailStateFilter = "all" | "unread" | "sent";
type BillingProviderFilter = "all" | "stripe" | "ccbill" | "paypal";
type BillingStatusFilter = "all" | "pending" | "completed" | "failed" | "refunded" | "canceled";


const DEVTOOLS_TOTP_INPUT_STORAGE_KEY = "devtools:totp:input";
const DEVTOOLS_TOTP_PERSIST_STORAGE_KEY = "devtools:totp:persist";

type SmsBubbleGroup = {
  key: string;
  direction: "inbound" | "outbound" | "unknown";
  fromLabel: string;
  toLabel: string;
  messages: ReturnType<typeof useDevtoolsSmsConversations>["messages"];
};

const formatTimestamp = (iso?: string) => {
  if (!iso) return "Unknown";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString();
};

const formatAmount = (amount: number, currency = "usd") => {
  const safeCurrency = currency || "usd";
  try {
    return new Intl.NumberFormat("en-US", { style: "currency", currency: safeCurrency.toUpperCase() }).format(amount);
  } catch {
    return `${amount.toFixed(2)} ${safeCurrency.toUpperCase()}`;
  }
};

const sortBySentAtAscending = <T extends { sent_at: string }>(items: T[]) =>
  [...items].sort((a, b) => (a.sent_at < b.sent_at ? -1 : 1));

export default function DevToolsLogUiPage() {
  const [activeTab, setActiveTab] = useState("email");

  const [selectedMailbox, setSelectedMailbox] = useState<string>(ALL_INBOXES);
  const [selectedThreadId, setSelectedThreadId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [stateFilter, setStateFilter] = useState<EmailStateFilter>("all");

  const [smsQuery, setSmsQuery] = useState("");
  const [selectedConversationId, setSelectedConversationId] = useState<string | null>(null);
  const [selectedSmsMessageId, setSelectedSmsMessageId] = useState<string | null>(null);

  const [billingProvider, setBillingProvider] = useState<BillingProviderFilter>("all");
  const [billingStatus, setBillingStatus] = useState<BillingStatusFilter>("all");
  const [billingFrom, setBillingFrom] = useState("");
  const [billingTo, setBillingTo] = useState("");

  const [mfaInput, setMfaInput] = useState("");
  const [persistMfaInput, setPersistMfaInput] = useState(false);
  const [mfaConfig, setMfaConfig] = useState<TotpConfig | null>(null);
  const [mfaErrors, setMfaErrors] = useState<string[]>([]);
  const [mfaWarnings, setMfaWarnings] = useState<string[]>([]);
  const [mfaCode, setMfaCode] = useState<string | null>(null);
  const [mfaSecondsRemaining, setMfaSecondsRemaining] = useState<number>(30);
  const [mfaPeriodSeconds, setMfaPeriodSeconds] = useState<number>(30);

  const emailQuery = useMemo(
    () => ({
      mailbox: selectedMailbox === ALL_INBOXES ? undefined : selectedMailbox,
      q: searchQuery.trim() || undefined,
      state: stateFilter,
      limit: 100,
    }),
    [searchQuery, selectedMailbox, stateFilter],
  );

  const billingQuery = useMemo(
    () => ({
      provider: billingProvider === "all" ? undefined : billingProvider,
      status: billingStatus === "all" ? undefined : billingStatus,
      from: billingFrom || undefined,
      to: billingTo || undefined,
      limit: 50,
    }),
    [billingFrom, billingProvider, billingStatus, billingTo],
  );

  const emailData = useDevtoolsEmailMessages(emailQuery, activeTab === "email");
  const smsData = useDevtoolsSmsConversations({ q: smsQuery.trim() || undefined, limit: 100 }, activeTab === "sms");
  const billingLedger = useDevtoolsBillingLedger(billingQuery, activeTab === "billing");
  const billingSummary = useDevtoolsBillingSummary(
    {
      provider: billingQuery.provider,
      status: billingQuery.status,
      from: billingQuery.from,
      to: billingQuery.to,
    },
    activeTab === "billing",
  );

  useEffect(() => {
    const threadIds = new Set(emailData.threads.map((thread) => thread.id));
    if (selectedThreadId && threadIds.has(selectedThreadId)) return;
    setSelectedThreadId(emailData.threads[0]?.id ?? null);
  }, [emailData.threads, selectedThreadId]);

  const orderedConversations = useMemo(
    () => [...smsData.conversations].sort((a, b) => (a.latest_message_at < b.latest_message_at ? 1 : -1)),
    [smsData.conversations],
  );

  useEffect(() => {
    const conversationIds = new Set(orderedConversations.map((conversation) => conversation.id));
    if (selectedConversationId && conversationIds.has(selectedConversationId)) return;
    setSelectedConversationId(orderedConversations[0]?.id ?? null);
  }, [orderedConversations, selectedConversationId]);

  const selectedThread = emailData.threads.find((thread) => thread.id === selectedThreadId) ?? null;
  const selectedMessages = sortBySentAtAscending(
    emailData.messages.filter((message) => message.thread_id === selectedThreadId),
  );
  const selectedMessage = selectedMessages[selectedMessages.length - 1] ?? null;

  const selectedConversation = orderedConversations.find((conversation) => conversation.id === selectedConversationId) ?? null;
  const selectedConversationMessages = sortBySentAtAscending(
    smsData.messages.filter((message) => message.conversation_id === selectedConversationId),
  );

  useEffect(() => {
    const messageIds = new Set(selectedConversationMessages.map((message) => message.id));
    if (selectedSmsMessageId && messageIds.has(selectedSmsMessageId)) return;
    setSelectedSmsMessageId(selectedConversationMessages[selectedConversationMessages.length - 1]?.id ?? null);
  }, [selectedConversationMessages, selectedSmsMessageId]);

  const selectedSmsMessage = selectedConversationMessages.find((message) => message.id === selectedSmsMessageId) ?? null;

  const smsBubbleGroups = useMemo(() => {
    const groups: SmsBubbleGroup[] = [];

    selectedConversationMessages.forEach((message, index) => {
      const fromLabel = message.from_number || "Unknown sender";
      const toLabel = message.to_number || "Unknown recipient";
      const prev = selectedConversationMessages[index - 1];
      const canGroupWithPrevious =
        prev &&
        prev.direction === message.direction &&
        (prev.from_number || "") === (message.from_number || "") &&
        (prev.to_number || "") === (message.to_number || "");

      if (!canGroupWithPrevious) {
        groups.push({
          key: `group-${message.id}`,
          direction: message.direction,
          fromLabel,
          toLabel,
          messages: [message],
        });
        return;
      }

      const lastGroup = groups[groups.length - 1];
      if (lastGroup) {
        lastGroup.messages.push(message);
      }
    });

    return groups;
  }, [selectedConversationMessages]);

  useEffect(() => {
    try {
      setPersistMfaInput(localStorage.getItem(DEVTOOLS_TOTP_PERSIST_STORAGE_KEY) === "1");
      const savedInput = localStorage.getItem(DEVTOOLS_TOTP_INPUT_STORAGE_KEY);
      if (savedInput) setMfaInput(savedInput);
    } catch {
      // no-op for storage access errors
    }
  }, []);

  useEffect(() => {
    const result = parseTotpConfigInput(mfaInput);
    setMfaErrors(result.errors);
    setMfaWarnings(result.warnings);
    setMfaConfig(result.ok ? result.config ?? null : null);
    if (!result.ok) setMfaCode(null);
  }, [mfaInput]);

  useEffect(() => {
    try {
      localStorage.setItem(DEVTOOLS_TOTP_PERSIST_STORAGE_KEY, persistMfaInput ? "1" : "0");
      if (persistMfaInput && mfaInput.trim()) {
        localStorage.setItem(DEVTOOLS_TOTP_INPUT_STORAGE_KEY, mfaInput);
      } else {
        localStorage.removeItem(DEVTOOLS_TOTP_INPUT_STORAGE_KEY);
      }
    } catch {
      // no-op for storage access errors
    }
  }, [mfaInput, persistMfaInput]);

  useEffect(() => {
    if (activeTab !== "mfa" || !mfaConfig) return;

    let cancelled = false;
    const tick = async () => {
      try {
        const next = await generateTotpCode(mfaConfig);
        if (cancelled) return;
        setMfaCode(next.code);
        setMfaSecondsRemaining(next.secondsRemaining);
        setMfaPeriodSeconds(next.periodSeconds);
      } catch {
        if (!cancelled) {
          setMfaCode(null);
          setMfaErrors((prev) => (prev.includes("Failed to generate TOTP code from the provided config.") ? prev : [...prev, "Failed to generate TOTP code from the provided config."]));
        }
      }
    };

    void tick();
    const id = window.setInterval(() => {
      void tick();
    }, 1000);

    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [activeTab, mfaConfig]);

  const handleMfaReset = () => {
    setMfaInput("");
    setMfaCode(null);
    setMfaErrors([]);
    setMfaWarnings([]);
    setMfaConfig(null);
    setMfaSecondsRemaining(30);
    setMfaPeriodSeconds(30);
    if (!persistMfaInput) {
      try {
        localStorage.removeItem(DEVTOOLS_TOTP_INPUT_STORAGE_KEY);
      } catch {
        // no-op
      }
    }
  };

  return (
    <div className="space-y-6 pb-24 md:pb-6">
      <PageHeader
        title="Dev Tools Log UI"
        description="Read-only internal log explorer for Email, SMS, MFA, and Billing dev artifacts."
      />

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-2 sm:grid-cols-4">
          <TabsTrigger value="email">Email</TabsTrigger>
          <TabsTrigger value="sms">SMS</TabsTrigger>
          <TabsTrigger value="mfa">MFA (TOTP)</TabsTrigger>
          <TabsTrigger value="billing">Billing</TabsTrigger>
        </TabsList>

        <TabsContent value="email" className="space-y-4">
          <div className="flex flex-col gap-3 rounded-lg border bg-card p-3 md:flex-row md:items-center">
            <Input
              placeholder="Search subject, body, sender, recipient"
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              className="md:max-w-md"
              aria-label="Search email logs"
            />
            <Select value={stateFilter} onValueChange={(value) => setStateFilter(value as EmailStateFilter)}>
              <SelectTrigger className="w-full md:w-44" aria-label="State filter">
                <SelectValue placeholder="Filter state" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="unread">Unread</SelectItem>
                <SelectItem value="sent">Sent</SelectItem>
              </SelectContent>
            </Select>
            {emailData.parseWarnings.length > 0 && (
              <Badge variant="secondary">Warnings: {emailData.parseWarnings.length}</Badge>
            )}
          </div>

          {emailData.errorMessage && (
            <div className="rounded-lg border border-destructive/60 bg-destructive/10 p-3 text-sm text-destructive">
              Unable to load email logs: {emailData.errorMessage}
            </div>
          )}

          {emailData.isLoading ? (
            <div className="rounded-lg border bg-card p-6 text-sm text-muted-foreground">Loading email logs…</div>
          ) : (
            <div className="grid min-h-[520px] grid-cols-1 overflow-hidden rounded-lg border bg-card lg:grid-cols-[240px_320px_1fr]">
              <aside className="border-b p-3 lg:border-b-0 lg:border-r">
                <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Mailboxes</div>
                <div className="space-y-1">
                  <button
                    type="button"
                    className={`w-full rounded-md px-3 py-2 text-left text-sm ${
                      selectedMailbox === ALL_INBOXES ? "bg-primary/10 text-primary" : "hover:bg-accent"
                    }`}
                    onClick={() => setSelectedMailbox(ALL_INBOXES)}
                  >
                    All Inboxes
                  </button>
                  {emailData.mailboxes.map((mailbox) => (
                    <button
                      key={mailbox.id}
                      type="button"
                      className={`w-full rounded-md px-3 py-2 text-left text-sm ${
                        selectedMailbox === mailbox.mailbox ? "bg-primary/10 text-primary" : "hover:bg-accent"
                      }`}
                      onClick={() => setSelectedMailbox(mailbox.mailbox)}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate">{mailbox.mailbox}</span>
                        <Badge variant="outline">{mailbox.thread_count}</Badge>
                      </div>
                    </button>
                  ))}
                </div>
              </aside>

              <section className="border-b p-3 lg:border-b-0 lg:border-r">
                <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Threads</div>
                {emailData.threads.length === 0 ? (
                  <div className="rounded border border-dashed p-3 text-sm text-muted-foreground">No threads for selected filters.</div>
                ) : (
                  <div className="space-y-1">
                    {emailData.threads.map((thread) => (
                      <button
                        key={thread.id}
                        type="button"
                        className={`w-full rounded-md px-3 py-2 text-left text-sm ${
                          thread.id === selectedThreadId ? "bg-primary/10 text-primary" : "hover:bg-accent"
                        }`}
                        onClick={() => setSelectedThreadId(thread.id)}
                      >
                        <div className="truncate font-medium">{thread.subject || "(no subject)"}</div>
                        <div className="truncate text-xs text-muted-foreground">{thread.mailbox}</div>
                        <div className="mt-1 text-xs text-muted-foreground">{formatTimestamp(thread.latest_message_at)}</div>
                      </button>
                    ))}
                  </div>
                )}
              </section>

              <section className="p-3">
                {!selectedThread || !selectedMessage ? (
                  <div className="rounded border border-dashed p-4 text-sm text-muted-foreground">
                    Select a thread to view message details.
                  </div>
                ) : (
                  <div className="space-y-3">
                    <div>
                      <h2 className="text-lg font-semibold">{selectedThread.subject || "(no subject)"}</h2>
                      <div className="mt-1 text-xs text-muted-foreground">
                        {selectedMessages.length} message{selectedMessages.length === 1 ? "" : "s"} in thread
                      </div>
                    </div>
                    <Separator />
                    <dl className="grid grid-cols-1 gap-2 text-sm md:grid-cols-2">
                      <div>
                        <dt className="text-xs text-muted-foreground">Mailbox</dt>
                        <dd>{selectedMessage.mailbox}</dd>
                      </div>
                      <div>
                        <dt className="text-xs text-muted-foreground">Sent</dt>
                        <dd>{formatTimestamp(selectedMessage.sent_at)}</dd>
                      </div>
                      <div>
                        <dt className="text-xs text-muted-foreground">From</dt>
                        <dd>{selectedMessage.from_email || "Unknown"}</dd>
                      </div>
                      <div>
                        <dt className="text-xs text-muted-foreground">To</dt>
                        <dd>{selectedMessage.to_emails.join(", ") || "Unknown"}</dd>
                      </div>
                      <div>
                        <dt className="text-xs text-muted-foreground">Event</dt>
                        <dd>{selectedMessage.event_kind}</dd>
                      </div>
                      <div>
                        <dt className="text-xs text-muted-foreground">Status</dt>
                        <dd>{selectedMessage.status || "n/a"}</dd>
                      </div>
                    </dl>
                    <Separator />
                    <div>
                      <div className="mb-1 text-xs text-muted-foreground">Body</div>
                      <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3 text-sm">
                        {selectedMessage.body_text || selectedMessage.body_html || "(empty body)"}
                      </pre>
                    </div>
                  </div>
                )}
              </section>
            </div>
          )}
        </TabsContent>

        <TabsContent value="sms" className="space-y-4">
          <div className="flex flex-col gap-3 rounded-lg border bg-card p-3 md:flex-row md:items-center">
            <Input
              placeholder="Search phone number or message text"
              value={smsQuery}
              onChange={(event) => setSmsQuery(event.target.value)}
              className="md:max-w-md"
              aria-label="Search sms logs"
            />
            {smsData.parseWarnings.length > 0 && (
              <Badge variant="secondary">Warnings: {smsData.parseWarnings.length}</Badge>
            )}
            <Badge variant="outline">Read-only</Badge>
          </div>

          {smsData.errorMessage && (
            <div className="rounded-lg border border-destructive/60 bg-destructive/10 p-3 text-sm text-destructive">
              Unable to load SMS logs: {smsData.errorMessage}
            </div>
          )}

          {smsData.isLoading ? (
            <div className="rounded-lg border bg-card p-6 text-sm text-muted-foreground">Loading SMS logs…</div>
          ) : (
            <div className="grid min-h-[520px] grid-cols-1 overflow-hidden rounded-lg border bg-card lg:grid-cols-[280px_1fr_300px]">
              <aside className="border-b p-3 lg:border-b-0 lg:border-r">
                <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Conversations</div>
                {orderedConversations.length === 0 ? (
                  <div className="rounded border border-dashed p-3 text-sm text-muted-foreground">No conversations found.</div>
                ) : (
                  <div className="space-y-1">
                    {orderedConversations.map((conversation) => (
                      <button
                        key={conversation.id}
                        type="button"
                        className={`w-full rounded-md px-3 py-2 text-left text-sm ${
                          conversation.id === selectedConversationId ? "bg-primary/10 text-primary" : "hover:bg-accent"
                        }`}
                        onClick={() => setSelectedConversationId(conversation.id)}
                      >
                        <div className="truncate font-medium">{conversation.participant_numbers.join(", ") || "Unknown"}</div>
                        <div className="mt-1 line-clamp-1 text-xs text-muted-foreground">
                          {conversation.latest_preview || "No preview"}
                        </div>
                        <div className="mt-1 text-xs text-muted-foreground">{formatTimestamp(conversation.latest_message_at)}</div>
                      </button>
                    ))}
                  </div>
                )}
              </aside>

              <section className="border-b p-3 lg:border-b-0 lg:border-r">
                <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Thread</div>
                {!selectedConversation ? (
                  <div className="rounded border border-dashed p-4 text-sm text-muted-foreground">
                    Select a conversation to view messages.
                  </div>
                ) : selectedConversationMessages.length === 0 ? (
                  <div className="rounded border border-dashed p-4 text-sm text-muted-foreground">No messages in this conversation.</div>
                ) : (
                  <div className="space-y-3">
                    {smsBubbleGroups.map((group) => {
                      const outbound = group.direction === "outbound";
                      return (
                        <div
                          key={group.key}
                          className={`flex flex-col gap-1 ${outbound ? "items-end" : "items-start"}`}
                        >
                          <div className="text-[11px] text-muted-foreground">{`${group.fromLabel} → ${group.toLabel}`}</div>
                          {group.messages.map((message) => (
                            <button
                              key={message.id}
                              type="button"
                              className={`max-w-[82%] rounded-2xl px-3 py-2 text-left text-sm ${
                                outbound
                                  ? "bg-primary text-primary-foreground"
                                  : "bg-muted text-foreground"
                              } ${selectedSmsMessageId === message.id ? "ring-2 ring-ring" : ""}`}
                              onClick={() => setSelectedSmsMessageId(message.id)}
                            >
                              <div>{message.body_text || "(empty message)"}</div>
                              <div className={`mt-1 text-[11px] ${outbound ? "text-primary-foreground/80" : "text-muted-foreground"}`}>
                                {formatTimestamp(message.sent_at)}
                              </div>
                            </button>
                          ))}
                        </div>
                      );
                    })}
                  </div>
                )}
              </section>

              <aside className="p-3">
                <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Message metadata</div>
                {!selectedSmsMessage ? (
                  <div className="rounded border border-dashed p-4 text-sm text-muted-foreground">
                    Select a bubble to inspect status and IDs.
                  </div>
                ) : (
                  <dl className="space-y-2 text-sm">
                    <div>
                      <dt className="text-xs text-muted-foreground">Conversation ID</dt>
                      <dd className="break-all">{selectedSmsMessage.conversation_id}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-muted-foreground">Message ID</dt>
                      <dd className="break-all">{selectedSmsMessage.id}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-muted-foreground">Provider message ID</dt>
                      <dd className="break-all">{selectedSmsMessage.provider_message_id || "n/a"}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-muted-foreground">Direction</dt>
                      <dd>{selectedSmsMessage.direction}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-muted-foreground">From</dt>
                      <dd>{selectedSmsMessage.from_number || "Unknown"}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-muted-foreground">To</dt>
                      <dd>{selectedSmsMessage.to_number || "Unknown"}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-muted-foreground">Status</dt>
                      <dd>{selectedSmsMessage.status || "n/a"}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-muted-foreground">Event kind</dt>
                      <dd>{selectedSmsMessage.event_kind}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-muted-foreground">Sent</dt>
                      <dd>{formatTimestamp(selectedSmsMessage.sent_at)}</dd>
                    </div>
                  </dl>
                )}
              </aside>
            </div>
          )}
        </TabsContent>

        <TabsContent value="mfa" className="space-y-4">
          <div className="rounded-lg border bg-card p-4 text-sm">
            <p className="text-muted-foreground">
              Local-only tool: pasted TOTP configuration is parsed and used entirely in your browser. Secrets are never sent to backend APIs.
            </p>
          </div>

          <div className="grid gap-4 lg:grid-cols-[1.2fr_1fr]">
            <section className="rounded-lg border bg-card p-4 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="font-semibold">TOTP configuration</h3>
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span>Persist locally</span>
                  <Switch checked={persistMfaInput} onCheckedChange={setPersistMfaInput} aria-label="Persist TOTP config locally" />
                </div>
              </div>

              <Textarea
                value={mfaInput}
                onChange={(event) => setMfaInput(event.target.value)}
                placeholder="Paste otpauth:// URI or raw Base32 secret"
                className="min-h-[140px]"
                aria-label="Paste TOTP configuration"
              />

              {mfaErrors.length > 0 && (
                <div className="rounded-md border border-destructive/60 bg-destructive/10 p-3 text-sm text-destructive space-y-1">
                  {mfaErrors.map((error) => (
                    <div key={error}>{error}</div>
                  ))}
                </div>
              )}

              {mfaWarnings.length > 0 && (
                <div className="rounded-md border bg-muted p-3 text-sm text-muted-foreground space-y-1">
                  {mfaWarnings.map((warning) => (
                    <div key={warning}>{warning}</div>
                  ))}
                </div>
              )}

              <div className="flex gap-2">
                <Button type="button" variant="outline" onClick={handleMfaReset}>Clear / Reset</Button>
              </div>
            </section>

            <section className="rounded-lg border bg-card p-4 space-y-3">
              <h3 className="font-semibold">Live code</h3>
              {!mfaConfig || mfaErrors.length > 0 ? (
                <div className="rounded border border-dashed p-4 text-sm text-muted-foreground">
                  Provide a valid TOTP configuration to generate live codes.
                </div>
              ) : (
                <>
                  <div className="rounded-md bg-muted p-4">
                    <div className="text-xs uppercase tracking-wide text-muted-foreground">Current code</div>
                    <div className="mt-2 font-mono text-4xl tracking-[0.25em]">{mfaCode ?? "------"}</div>
                  </div>

                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div className="rounded-md border p-3">
                      <div className="text-xs uppercase tracking-wide text-muted-foreground">Rollover in</div>
                      <div className="mt-1 text-xl font-semibold">{mfaSecondsRemaining}s</div>
                    </div>
                    <div className="rounded-md border p-3">
                      <div className="text-xs uppercase tracking-wide text-muted-foreground">Cadence</div>
                      <div className="mt-1 text-xl font-semibold">{mfaPeriodSeconds}s</div>
                    </div>
                  </div>

                  <dl className="space-y-2 text-sm">
                    <div>
                      <dt className="text-xs text-muted-foreground">Mode</dt>
                      <dd>{mfaConfig.mode}</dd>
                    </div>
                    <div>
                      <dt className="text-xs text-muted-foreground">Algorithm / digits</dt>
                      <dd>{mfaConfig.algorithm} / {mfaConfig.digits}</dd>
                    </div>
                    {mfaConfig.issuer && (
                      <div>
                        <dt className="text-xs text-muted-foreground">Issuer</dt>
                        <dd>{mfaConfig.issuer}</dd>
                      </div>
                    )}
                    {mfaConfig.accountName && (
                      <div>
                        <dt className="text-xs text-muted-foreground">Account</dt>
                        <dd>{mfaConfig.accountName}</dd>
                      </div>
                    )}
                  </dl>
                </>
              )}
            </section>
          </div>
        </TabsContent>

        <TabsContent value="billing" className="space-y-4">
          <div className="grid gap-3 rounded-lg border bg-card p-3 md:grid-cols-2 xl:grid-cols-5">
            <Select value={billingProvider} onValueChange={(value) => setBillingProvider(value as BillingProviderFilter)}>
              <SelectTrigger aria-label="Billing provider filter">
                <SelectValue placeholder="Provider" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All providers</SelectItem>
                <SelectItem value="stripe">Stripe</SelectItem>
                <SelectItem value="ccbill">CCBill</SelectItem>
                <SelectItem value="paypal">PayPal</SelectItem>
              </SelectContent>
            </Select>

            <Select value={billingStatus} onValueChange={(value) => setBillingStatus(value as BillingStatusFilter)}>
              <SelectTrigger aria-label="Billing status filter">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All statuses</SelectItem>
                <SelectItem value="pending">Pending</SelectItem>
                <SelectItem value="completed">Completed</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
                <SelectItem value="refunded">Refunded</SelectItem>
                <SelectItem value="canceled">Canceled</SelectItem>
              </SelectContent>
            </Select>

            <Input type="datetime-local" aria-label="Billing from date" value={billingFrom} onChange={(e) => setBillingFrom(e.target.value)} />
            <Input type="datetime-local" aria-label="Billing to date" value={billingTo} onChange={(e) => setBillingTo(e.target.value)} />
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setBillingProvider("all");
                setBillingStatus("all");
                setBillingFrom("");
                setBillingTo("");
              }}
            >
              Reset filters
            </Button>
          </div>

          {(billingLedger.errorMessage || billingSummary.errorMessage) && (
            <div className="rounded-lg border border-destructive/60 bg-destructive/10 p-3 text-sm text-destructive">
              Unable to load billing logs: {billingLedger.errorMessage || billingSummary.errorMessage}
            </div>
          )}

          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-lg border bg-card p-4">
              <div className="text-xs uppercase tracking-wide text-muted-foreground">Gross inflow</div>
              <div className="mt-2 text-2xl font-semibold">{formatAmount(billingSummary.data?.gross_inflow ?? 0)}</div>
            </div>
            <div className="rounded-lg border bg-card p-4">
              <div className="text-xs uppercase tracking-wide text-muted-foreground">Fees</div>
              <div className="mt-2 text-2xl font-semibold">{formatAmount(billingSummary.data?.fees ?? 0)}</div>
            </div>
            <div className="rounded-lg border bg-card p-4">
              <div className="text-xs uppercase tracking-wide text-muted-foreground">Net balance</div>
              <div className="mt-2 text-2xl font-semibold">{formatAmount(billingSummary.data?.net_total_balance ?? 0)}</div>
            </div>
            <div className="rounded-lg border bg-card p-4">
              <div className="text-xs uppercase tracking-wide text-muted-foreground">Transactions</div>
              <div className="mt-2 text-2xl font-semibold">{billingSummary.data?.transaction_count ?? 0}</div>
            </div>
          </div>

          {billingLedger.isLoading ? (
            <div className="rounded-lg border bg-card p-6 text-sm text-muted-foreground">Loading billing ledger…</div>
          ) : billingLedger.isEmpty ? (
            <div className="rounded-lg border border-dashed p-6 text-sm text-muted-foreground">No ledger entries for selected filters.</div>
          ) : (
            <div className="rounded-lg border bg-card">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Occurred</TableHead>
                    <TableHead>Provider</TableHead>
                    <TableHead>Event</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Amount</TableHead>
                    <TableHead className="text-right">Fee</TableHead>
                    <TableHead className="text-right">Net</TableHead>
                    <TableHead>External ID</TableHead>
                    <TableHead>Source</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {billingLedger.entries.map((entry) => (
                    <TableRow key={entry.id}>
                      <TableCell className="whitespace-nowrap text-xs">{formatTimestamp(entry.occurred_at)}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{entry.provider}</Badge>
                      </TableCell>
                      <TableCell className="text-xs">{entry.event_type}</TableCell>
                      <TableCell>
                        <Badge variant={entry.status === "completed" ? "default" : "secondary"}>{entry.status}</Badge>
                      </TableCell>
                      <TableCell className="text-right text-xs">{formatAmount(entry.amount, entry.currency)}</TableCell>
                      <TableCell className="text-right text-xs">{formatAmount(entry.fee, entry.currency)}</TableCell>
                      <TableCell className="text-right text-xs">{formatAmount(entry.net, entry.currency)}</TableCell>
                      <TableCell className="max-w-[180px] truncate font-mono text-xs">{entry.external_id || "-"}</TableCell>
                      <TableCell>
                        <Dialog>
                          <DialogTrigger asChild>
                            <Button variant="outline" size="sm">View raw</Button>
                          </DialogTrigger>
                          <DialogContent className="max-h-[85vh] max-w-3xl overflow-auto">
                            <DialogHeader>
                              <DialogTitle>Raw billing payload</DialogTitle>
                              <DialogDescription>Read-only source payload details for this ledger entry.</DialogDescription>
                            </DialogHeader>
                            <div className="space-y-2 text-sm">
                              <div>
                                <span className="text-muted-foreground">Source path: </span>
                                <span className="font-mono text-xs">{entry.source_path || "n/a"}</span>
                              </div>
                              <div>
                                <span className="text-muted-foreground">External ID: </span>
                                <span className="font-mono text-xs">{entry.external_id || "n/a"}</span>
                              </div>
                              <pre className="overflow-auto rounded-md bg-muted p-3 text-xs">
                                {JSON.stringify(entry.raw_payload, null, 2)}
                              </pre>
                            </div>
                          </DialogContent>
                        </Dialog>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>

              <div className="flex items-center justify-between gap-3 border-t p-3">
                <div className="text-xs text-muted-foreground">
                  Showing {billingLedger.entries.length} loaded entries for the selected scope.
                </div>
                {billingLedger.hasNextPage && (
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => billingLedger.fetchNextPage()}
                    disabled={billingLedger.isFetchingNextPage}
                  >
                    {billingLedger.isFetchingNextPage ? "Loading…" : "Load more"}
                  </Button>
                )}
              </div>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
