import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { MessageSquare, Send } from "lucide-react";

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
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ApiError } from "@/api/client";
import { getContacts } from "@/api/endpoints/contacts";
import {
  listContactSmsLog,
  sendContactSms,
  type CrmContactSmsOut,
} from "@/api/endpoints/crmSms";

const MAX_LEN = 1600;

function fmtTs(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function estimateSegments(body: string): number {
  if (!body) return 0;
  // GSM-7 single segment = 160 chars; concatenated = 153 chars/segment.
  return body.length <= 160 ? 1 : Math.ceil(body.length / 153);
}

const STATUS_TONE: Record<string, string> = {
  sent: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300",
  dev_logged: "bg-sky-100 text-sky-800 dark:bg-sky-900/40 dark:text-sky-300",
  suppressed: "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300",
  rate_limited: "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300",
  failed: "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300",
  disabled: "bg-muted text-muted-foreground",
};

function StatusBadge({ status }: { status: string }) {
  const tone = STATUS_TONE[status] ?? "bg-muted text-muted-foreground";
  return (
    <span
      className={`inline-flex rounded px-2 py-0.5 text-xs font-medium ${tone}`}
    >
      {status}
    </span>
  );
}

export default function CrmSmsPage() {
  const qc = useQueryClient();
  const [contactId, setContactId] = useState<string>("");
  const [body, setBody] = useState("");

  const contactsQuery = useQuery({
    queryKey: ["contacts"],
    queryFn: getContacts,
  });

  // The live GET /ui/crm/contacts/{id}/sms lists ALL sends by the sender,
  // ignoring the path id. We pass the selected (or a placeholder) id and show
  // the full outbound history. The query also surfaces the feature flag state.
  const logQuery = useQuery({
    queryKey: ["crm-sms-log"],
    queryFn: () => listContactSmsLog(contactId || "_self", { limit: 100 }),
    retry: false,
  });

  const sendMut = useMutation({
    mutationFn: () => sendContactSms(contactId, { body }),
    onSuccess: (res: CrmContactSmsOut) => {
      const ok = res.status === "sent" || res.status === "dev_logged";
      if (ok) {
        toast.success(`SMS ${res.status} to ${res.contact_phone}`);
        setBody("");
      } else if (res.status === "suppressed") {
        toast.warning("This number has opted out of SMS.");
      } else if (res.status === "rate_limited") {
        toast.warning("Per-number daily SMS limit reached.");
      } else if (res.status === "disabled") {
        toast.warning("SMS sending is disabled by the operator.");
      } else {
        toast.error(`SMS failed (status: ${res.status}).`);
      }
      qc.invalidateQueries({ queryKey: ["crm-sms-log"] });
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError) {
        if (err.status === 429) {
          toast.error("SMS rate limit reached. Please try again later.");
          return;
        }
        if (err.status === 404) {
          toast.error(
            err.detail ||
              "This contact has no phone number, or the contact was not found.",
          );
          return;
        }
        toast.error(err.detail || "Failed to send SMS.");
        return;
      }
      toast.error("Failed to send SMS.");
    },
  });

  const contacts = contactsQuery.data ?? [];
  const segments = useMemo(() => estimateSegments(body), [body]);
  const canSend =
    !!contactId && body.trim().length > 0 && body.length <= MAX_LEN;

  // Feature-flag-off detection: the log endpoint 404s when disabled.
  const flagOff =
    logQuery.isError &&
    logQuery.error instanceof ApiError &&
    logQuery.error.status === 404;

  if (flagOff) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="SMS Compose"
          description="Send a text message to a CRM contact."
        />
        <Card>
          <CardHeader>
            <CardTitle>SMS is not enabled</CardTitle>
            <CardDescription>
              The CRM Contact SMS feature is turned off for this workspace.
              Ask an operator to enable{" "}
              <code className="rounded bg-muted px-1">
                CRM_CONTACT_SMS_ENABLED
              </code>
              .
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="SMS Compose"
        description="Send a text message to a CRM contact and review send history."
      />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <MessageSquare className="h-4 w-4" /> Compose
          </CardTitle>
          <CardDescription>
            Choose a contact and write up to {MAX_LEN} characters.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="crm-sms-contact">Contact</Label>
            <Select value={contactId} onValueChange={setContactId}>
              <SelectTrigger id="crm-sms-contact" className="max-w-sm">
                <SelectValue
                  placeholder={
                    contactsQuery.isLoading
                      ? "Loading contacts…"
                      : contacts.length === 0
                        ? "No contacts available"
                        : "Select a contact"
                  }
                />
              </SelectTrigger>
              <SelectContent>
                {contacts.map((c) => (
                  <SelectItem key={c.contact_id} value={c.contact_id}>
                    {c.display_name || c.contact_id}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="crm-sms-body">Message</Label>
            <Textarea
              id="crm-sms-body"
              value={body}
              onChange={(e) => setBody(e.target.value.slice(0, MAX_LEN))}
              placeholder="Type your message…"
              rows={5}
            />
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>
                {body.length} / {MAX_LEN} characters
              </span>
              <span>
                {segments} segment{segments === 1 ? "" : "s"}
              </span>
            </div>
          </div>

          <div className="flex justify-end">
            <Button
              onClick={() => sendMut.mutate()}
              disabled={!canSend || sendMut.isPending}
            >
              <Send className="mr-2 h-4 w-4" />
              {sendMut.isPending ? "Sending…" : "Send SMS"}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Send history</CardTitle>
          <CardDescription>
            Recent outbound SMS sent by you.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {logQuery.isLoading ? (
            <p className="text-sm text-muted-foreground">Loading history…</p>
          ) : (logQuery.data?.items.length ?? 0) === 0 ? (
            <p className="text-sm text-muted-foreground">
              No SMS sent yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Sent</TableHead>
                  <TableHead>Contact</TableHead>
                  <TableHead>Phone</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Message ID</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(logQuery.data?.items ?? []).map((row) => (
                  <TableRow key={row.sms_id}>
                    <TableCell className="whitespace-nowrap">
                      {fmtTs(row.sent_at_ts)}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {row.contact_id}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {row.contact_phone}
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={row.status} />
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {row.message_id || "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          {logQuery.data?.cursor ? (
            <div className="mt-3 text-xs text-muted-foreground">
              <Badge variant="outline">More results available</Badge>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
