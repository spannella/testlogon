import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Megaphone, Plus, Send, RefreshCw, Trash2, Eye } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { ApiError } from "@/api/client";
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
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import {
  listCampaigns,
  createCampaign,
  deleteCampaign,
  sendCampaign,
  getCampaignAttribution,
  getAbResults,
  previewCampaignEmail,
  listEmailTemplates,
  type CrmCampaign,
  type CampaignType,
} from "@/api/endpoints/crmCampaigns";
import { CampaignsNotEnabled, isCampaignsDisabled } from "./CampaignsNotEnabled";

const CAMPAIGN_TYPES: CampaignType[] = ["email", "sms", "phone", "mail", "fax"];

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function money(cents?: number): string {
  const v = (cents ?? 0) / 100;
  return v.toLocaleString(undefined, { style: "currency", currency: "USD" });
}

function pct(n?: number): string {
  return `${((n ?? 0) * 100).toFixed(1)}%`;
}

function statusVariant(status: string): "default" | "secondary" | "outline" {
  if (status === "sent" || status === "active") return "default";
  if (status === "draft") return "secondary";
  return "outline";
}

// ─── Create dialog ─────────────────────────────────────────────────────────────

function CreateCampaignDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onCreated: () => void;
}) {
  const [name, setName] = useState("");
  const [objective, setObjective] = useState("");
  const [campaignType, setCampaignType] = useState<CampaignType>("email");
  const [budget, setBudget] = useState("");
  const [trackingCode, setTrackingCode] = useState("");
  const [emailTemplateId, setEmailTemplateId] = useState("");
  const [segments, setSegments] = useState("");
  const [contactLists, setContactLists] = useState("");

  const templatesQuery = useQuery({
    queryKey: ["crm-campaigns", "email-templates"],
    queryFn: () => listEmailTemplates({ limit: 100 }),
    enabled: open && campaignType === "email",
    retry: false,
  });

  const reset = () => {
    setName("");
    setObjective("");
    setCampaignType("email");
    setBudget("");
    setTrackingCode("");
    setEmailTemplateId("");
    setSegments("");
    setContactLists("");
  };

  const createMut = useMutation({
    mutationFn: () =>
      createCampaign({
        name: name.trim(),
        objective: objective.trim() || null,
        campaign_type: campaignType,
        budget_cents: budget ? Math.round(parseFloat(budget) * 100) : 0,
        tracking_code: trackingCode.trim() || null,
        email_template_id:
          campaignType === "email" && emailTemplateId ? emailTemplateId : null,
        segment_ids: segments
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        contact_list_ids: contactLists
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      }),
    onSuccess: () => {
      toast.success("Campaign created");
      reset();
      onOpenChange(false);
      onCreated();
    },
    onError: (e) =>
      toast.error(e instanceof ApiError ? e.detail : "Failed to create campaign"),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>New campaign</DialogTitle>
          <DialogDescription>
            Define a marketing wave and its targeting.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="cmp-name">Name</Label>
            <Input
              id="cmp-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Spring promo"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="cmp-objective">Objective</Label>
            <Textarea
              id="cmp-objective"
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              placeholder="What this campaign is for"
              rows={2}
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>Channel</Label>
              <Select
                value={campaignType}
                onValueChange={(v) => setCampaignType(v as CampaignType)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CAMPAIGN_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t.toUpperCase()}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cmp-budget">Budget (USD)</Label>
              <Input
                id="cmp-budget"
                type="number"
                min="0"
                step="0.01"
                value={budget}
                onChange={(e) => setBudget(e.target.value)}
                placeholder="0.00"
              />
            </div>
          </div>
          {campaignType === "email" && (
            <div className="space-y-1.5">
              <Label>Email template</Label>
              <Select
                value={emailTemplateId || "none"}
                onValueChange={(v) => setEmailTemplateId(v === "none" ? "" : v)}
              >
                <SelectTrigger>
                  <SelectValue placeholder="None" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">None</SelectItem>
                  {(templatesQuery.data?.templates ?? []).map((t) => (
                    <SelectItem key={t.template_id} value={t.template_id}>
                      {t.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          <div className="space-y-1.5">
            <Label htmlFor="cmp-track">Tracking code (open pixel)</Label>
            <Input
              id="cmp-track"
              value={trackingCode}
              onChange={(e) => setTrackingCode(e.target.value)}
              placeholder="spring2026"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="cmp-seg">Segment IDs</Label>
              <Input
                id="cmp-seg"
                value={segments}
                onChange={(e) => setSegments(e.target.value)}
                placeholder="comma-separated"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cmp-lists">Contact list IDs</Label>
              <Input
                id="cmp-lists"
                value={contactLists}
                onChange={(e) => setContactLists(e.target.value)}
                placeholder="comma-separated"
              />
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => createMut.mutate()}
            disabled={!name.trim() || createMut.isPending}
          >
            Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Detail panel ──────────────────────────────────────────────────────────────

function CampaignDetail({
  campaign,
  onChanged,
}: {
  campaign: CrmCampaign;
  onChanged: () => void;
}) {
  const qc = useQueryClient();
  const [sendOpen, setSendOpen] = useState(false);
  const [previewOpen, setPreviewOpen] = useState(false);

  const attributionQuery = useQuery({
    queryKey: ["crm-campaigns", "attribution", campaign.campaign_id],
    queryFn: () => getCampaignAttribution(campaign.campaign_id),
    retry: false,
  });

  const hasVariants = !!(campaign.variants && campaign.variants.length > 0);
  const abQuery = useQuery({
    queryKey: ["crm-campaigns", "ab", campaign.campaign_id],
    queryFn: () => getAbResults(campaign.campaign_id),
    enabled: hasVariants,
    retry: false,
  });

  const sendMut = useMutation({
    mutationFn: (dryRun: boolean) =>
      sendCampaign(campaign.campaign_id, { dry_run: dryRun }),
    onSuccess: (res) => {
      toast.success(
        res.dry_run
          ? `Dry run: ${res.total_resolved} resolved, ${res.total_skipped} skipped`
          : `Sent to ${res.total_sent} (resolved ${res.total_resolved}, skipped ${res.total_skipped})`,
      );
      setSendOpen(false);
      qc.invalidateQueries({
        queryKey: ["crm-campaigns", "attribution", campaign.campaign_id],
      });
      onChanged();
    },
    onError: (e) =>
      toast.error(e instanceof ApiError ? e.detail : "Send failed"),
  });

  const previewMut = useMutation({
    mutationFn: () => previewCampaignEmail(campaign.campaign_id, {}),
    onError: (e) =>
      toast.error(e instanceof ApiError ? e.detail : "Preview failed"),
  });

  const attribution = attributionQuery.data;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <div className="flex items-start justify-between gap-2">
            <div>
              <CardTitle className="flex items-center gap-2">
                {campaign.name}
                <Badge variant={statusVariant(campaign.status)}>
                  {campaign.status}
                </Badge>
                <Badge variant="outline">{campaign.campaign_type}</Badge>
              </CardTitle>
              <CardDescription>{campaign.objective || "No objective set"}</CardDescription>
            </div>
            <div className="flex gap-2">
              {campaign.campaign_type === "email" && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    previewMut.mutate();
                    setPreviewOpen(true);
                  }}
                >
                  <Eye className="mr-1 h-4 w-4" /> Preview
                </Button>
              )}
              <Button size="sm" onClick={() => setSendOpen(true)}>
                <Send className="mr-1 h-4 w-4" /> Send
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-3">
          <div>
            <p className="text-muted-foreground">Budget</p>
            <p className="font-medium">{money(campaign.budget_cents)}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Tracking code</p>
            <p className="font-medium">{campaign.tracking_code || "—"}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Segments</p>
            <p className="font-medium">{campaign.segment_ids.length}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Contact lists</p>
            <p className="font-medium">{campaign.contact_list_ids.length}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Created</p>
            <p className="font-medium">{fmt(campaign.created_at)}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Updated</p>
            <p className="font-medium">{fmt(campaign.updated_at)}</p>
          </div>
        </CardContent>
      </Card>

      {/* Attribution / ROI rollup (CMP-003 / CMP-007) */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Performance &amp; attribution</CardTitle>
          <CardDescription>Open-tracking and click rollup.</CardDescription>
        </CardHeader>
        <CardContent>
          {attributionQuery.isLoading ? (
            <Skeleton className="h-16 w-full" />
          ) : attribution ? (
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <Stat label="Sent" value={String(attribution.total_sent)} />
              <Stat label="Email sent" value={String(attribution.email_sent)} />
              <Stat
                label="Opens"
                value={`${attribution.open_count} (${pct(attribution.open_rate)})`}
              />
              <Stat
                label="Clicks"
                value={`${attribution.click_count} (${pct(attribution.click_rate)})`}
              />
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              No attribution data yet.
            </p>
          )}
        </CardContent>
      </Card>

      {/* A/B variant results (CMP-007) */}
      {hasVariants && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">A/B variant results</CardTitle>
          </CardHeader>
          <CardContent>
            {abQuery.isLoading ? (
              <Skeleton className="h-20 w-full" />
            ) : abQuery.data && abQuery.data.variant_stats.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Variant</TableHead>
                    <TableHead className="text-right">Sent</TableHead>
                    <TableHead className="text-right">Opens</TableHead>
                    <TableHead className="text-right">Clicks</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {abQuery.data.variant_stats.map((v) => (
                    <TableRow key={v.variant_id}>
                      <TableCell>{v.label || v.variant_id}</TableCell>
                      <TableCell className="text-right">{v.sent}</TableCell>
                      <TableCell className="text-right">
                        {v.opens} ({pct(v.open_rate)})
                      </TableCell>
                      <TableCell className="text-right">
                        {v.clicks} ({pct(v.click_rate)})
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p className="text-sm text-muted-foreground">No variant data.</p>
            )}
          </CardContent>
        </Card>
      )}

      {/* Send confirmation dialog */}
      <Dialog open={sendOpen} onOpenChange={setSendOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Send campaign</DialogTitle>
            <DialogDescription>
              Resolve targets from segments &amp; lists, then deliver via{" "}
              {campaign.campaign_type}. Run a dry run first to preview the audience
              size.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2 sm:gap-2">
            <Button
              variant="outline"
              onClick={() => sendMut.mutate(true)}
              disabled={sendMut.isPending}
            >
              Dry run
            </Button>
            <Button
              onClick={() => sendMut.mutate(false)}
              disabled={sendMut.isPending}
            >
              <Send className="mr-1 h-4 w-4" /> Send now
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Email preview dialog */}
      <Dialog open={previewOpen} onOpenChange={setPreviewOpen}>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Email preview</DialogTitle>
            <DialogDescription>{previewMut.data?.subject}</DialogDescription>
          </DialogHeader>
          {previewMut.isPending ? (
            <Skeleton className="h-40 w-full" />
          ) : previewMut.data ? (
            <div className="space-y-3">
              {previewMut.data.body_html ? (
                <div
                  className="rounded border p-3 text-sm"
                  // Preview of merged template HTML for the campaign owner.
                  dangerouslySetInnerHTML={{ __html: previewMut.data.body_html }}
                />
              ) : (
                <pre className="whitespace-pre-wrap rounded border p-3 text-sm">
                  {previewMut.data.body_text}
                </pre>
              )}
              {previewMut.data.merge_vars_missing.length > 0 && (
                <p className="text-xs text-amber-600">
                  Missing merge vars:{" "}
                  {previewMut.data.merge_vars_missing.join(", ")}
                </p>
              )}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No preview available.</p>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border p-3">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-lg font-semibold">{value}</p>
    </div>
  );
}

// ─── Page ──────────────────────────────────────────────────────────────────────

export default function CampaignsPage() {
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState<"" | CampaignType>("");
  const [statusFilter, setStatusFilter] = useState("");

  const listQuery = useQuery({
    queryKey: ["crm-campaigns", "list", typeFilter, statusFilter],
    queryFn: () =>
      listCampaigns({
        campaign_type: typeFilter || undefined,
        status: statusFilter || undefined,
        limit: 100,
      }),
    retry: false,
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteCampaign(id),
    onSuccess: () => {
      toast.success("Campaign deleted");
      setSelectedId(null);
      qc.invalidateQueries({ queryKey: ["crm-campaigns", "list"] });
    },
    onError: (e) =>
      toast.error(e instanceof ApiError ? e.detail : "Delete failed"),
  });

  const campaigns = listQuery.data?.campaigns ?? [];
  const selected = useMemo(
    () => campaigns.find((c) => c.campaign_id === selectedId) ?? null,
    [campaigns, selectedId],
  );

  if (listQuery.isError && isCampaignsDisabled(listQuery.error)) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Campaigns"
          description="Multi-channel marketing waves, targeting, and attribution."
        />
        <CampaignsNotEnabled status={(listQuery.error as ApiError)?.status} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Campaigns"
        description="Multi-channel marketing waves, targeting, and attribution."
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => listQuery.refetch()}
              disabled={listQuery.isFetching}
            >
              <RefreshCw className="mr-1 h-4 w-4" /> Refresh
            </Button>
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="mr-1 h-4 w-4" /> New campaign
            </Button>
          </>
        }
      />

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">All campaigns</CardTitle>
            <CardDescription>{listQuery.data?.count ?? 0} total</CardDescription>
            <div className="flex gap-2 pt-2">
              <Select
                value={typeFilter || "all"}
                onValueChange={(v) =>
                  setTypeFilter(v === "all" ? "" : (v as CampaignType))
                }
              >
                <SelectTrigger className="h-8 w-32">
                  <SelectValue placeholder="Channel" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All channels</SelectItem>
                  {CAMPAIGN_TYPES.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t.toUpperCase()}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Input
                className="h-8"
                placeholder="Status filter"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              />
            </div>
          </CardHeader>
          <CardContent>
            {listQuery.isLoading ? (
              <div className="space-y-2">
                <Skeleton className="h-12 w-full" />
                <Skeleton className="h-12 w-full" />
                <Skeleton className="h-12 w-full" />
              </div>
            ) : campaigns.length === 0 ? (
              <div className="flex flex-col items-center gap-2 py-10 text-center">
                <Megaphone className="h-8 w-8 text-muted-foreground" />
                <p className="text-sm text-muted-foreground">
                  No campaigns yet. Create your first marketing wave.
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                {campaigns.map((c) => (
                  <button
                    key={c.campaign_id}
                    onClick={() => setSelectedId(c.campaign_id)}
                    className={`flex w-full items-center justify-between rounded-lg border p-3 text-left transition hover:bg-accent ${
                      selectedId === c.campaign_id ? "border-primary bg-accent" : ""
                    }`}
                  >
                    <div className="min-w-0">
                      <p className="truncate font-medium">{c.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {c.campaign_type} · {money(c.budget_cents)}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={statusVariant(c.status)}>{c.status}</Badge>
                      <Trash2
                        className="h-4 w-4 text-muted-foreground hover:text-destructive"
                        onClick={(e) => {
                          e.stopPropagation();
                          if (
                            window.confirm(`Delete campaign "${c.name}"?`)
                          ) {
                            deleteMut.mutate(c.campaign_id);
                          }
                        }}
                      />
                    </div>
                  </button>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <div>
          {selected ? (
            <CampaignDetail
              campaign={selected}
              onChanged={() =>
                qc.invalidateQueries({ queryKey: ["crm-campaigns", "list"] })
              }
            />
          ) : (
            <Card>
              <CardContent className="flex flex-col items-center gap-2 py-20 text-center">
                <Megaphone className="h-8 w-8 text-muted-foreground" />
                <p className="text-sm text-muted-foreground">
                  Select a campaign to view performance, send, and preview.
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      <CreateCampaignDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={() =>
          qc.invalidateQueries({ queryKey: ["crm-campaigns", "list"] })
        }
      />
    </div>
  );
}
