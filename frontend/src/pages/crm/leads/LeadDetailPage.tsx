import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import {
  ArrowLeft,
  UserCheck,
  GitMerge,
  Trash2,
  Sparkles,
  History,
  Activity as ActivityIcon,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
import { Checkbox } from "@/components/ui/checkbox";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { ApiError } from "@/api/client";
import {
  getLead,
  updateLead,
  deleteLead,
  convertLead,
  assignLead,
  computeLeadScore,
  getScoreHistory,
  listActivities,
  logActivity,
  LEAD_STATUS_TRANSITIONS,
  LEAD_ACTIVITY_TYPES,
  type LeadStatus,
  type LeadConversionIn,
} from "@/api/endpoints/leads";
import { LeadsNotEnabled } from "./LeadsNotEnabled";
import { fmtTs, fmtCents, humanize, statusVariant, isNotEnabled, fullName } from "./leadUtils";

export default function LeadDetailPage() {
  const { leadId = "" } = useParams<{ leadId: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [assignDialog, setAssignDialog] = useState(false);
  const [assignee, setAssignee] = useState("");
  const [convertDialog, setConvertDialog] = useState(false);
  const [deleteDialog, setDeleteDialog] = useState(false);
  const [conv, setConv] = useState<LeadConversionIn>({
    create_account: false,
    create_opportunity: false,
  });

  const [actType, setActType] = useState<string>("note");
  const [actSubject, setActSubject] = useState("");
  const [actDesc, setActDesc] = useState("");

  const leadQuery = useQuery({
    queryKey: ["crm-lead", leadId],
    queryFn: () => getLead(leadId),
    retry: false,
    enabled: !!leadId,
  });

  const activitiesQuery = useQuery({
    queryKey: ["crm-lead-activities", leadId],
    queryFn: () => listActivities(leadId, { limit: 50 }),
    retry: false,
    enabled: !!leadId && !leadQuery.isError,
  });

  const scoreHistoryQuery = useQuery({
    queryKey: ["crm-lead-score-history", leadId],
    queryFn: () => getScoreHistory(leadId, { limit: 20 }),
    retry: false,
    enabled: !!leadId && !leadQuery.isError,
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["crm-lead", leadId] });
    qc.invalidateQueries({ queryKey: ["crm-lead-activities", leadId] });
    qc.invalidateQueries({ queryKey: ["crm-lead-score-history", leadId] });
    qc.invalidateQueries({ queryKey: ["crm-leads"] });
  };

  const onErr = (err: unknown, fallback: string) =>
    toast.error(err instanceof ApiError ? err.detail : fallback);

  const statusMut = useMutation({
    mutationFn: (status: LeadStatus) => updateLead(leadId, { status }),
    onSuccess: () => {
      toast.success("Status updated");
      invalidate();
    },
    onError: (e) => onErr(e, "Failed to update status"),
  });

  const scoreMut = useMutation({
    mutationFn: () => computeLeadScore(leadId),
    onSuccess: (r) => {
      toast.success(`Score recomputed: ${r.score}`);
      invalidate();
    },
    onError: (e) => onErr(e, "Failed to compute score"),
  });

  const assignMut = useMutation({
    mutationFn: () => assignLead(leadId, assignee.trim()),
    onSuccess: () => {
      toast.success("Lead assigned");
      setAssignDialog(false);
      setAssignee("");
      invalidate();
    },
    onError: (e) => onErr(e, "Failed to assign lead"),
  });

  const convertMut = useMutation({
    mutationFn: () => {
      const payload: LeadConversionIn = {
        create_account: conv.create_account,
        create_opportunity: conv.create_opportunity,
      };
      if (conv.create_account && conv.account_name?.trim())
        payload.account_name = conv.account_name.trim();
      if (conv.create_opportunity) {
        if (conv.opportunity_name?.trim()) payload.opportunity_name = conv.opportunity_name.trim();
        if (conv.opportunity_amount_cents != null)
          payload.opportunity_amount_cents = conv.opportunity_amount_cents;
      }
      return convertLead(leadId, payload);
    },
    onSuccess: (r) => {
      toast.success(
        r.opportunity
          ? `Lead converted — opportunity "${r.opportunity.name}" created`
          : "Lead converted",
      );
      setConvertDialog(false);
      invalidate();
    },
    onError: (e) => onErr(e, "Failed to convert lead"),
  });

  const deleteMut = useMutation({
    mutationFn: () => deleteLead(leadId),
    onSuccess: () => {
      toast.success("Lead deleted");
      navigate("/crm/leads");
    },
    onError: (e) => onErr(e, "Failed to delete lead"),
  });

  const activityMut = useMutation({
    mutationFn: () =>
      logActivity(leadId, {
        activity_type: actType,
        subject: actSubject.trim() || undefined,
        description: actDesc.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success("Activity logged");
      setActSubject("");
      setActDesc("");
      qc.invalidateQueries({ queryKey: ["crm-lead-activities", leadId] });
    },
    onError: (e) => onErr(e, "Failed to log activity"),
  });

  if (leadQuery.isError && isNotEnabled(leadQuery.error)) {
    return (
      <div className="space-y-6">
        <PageHeader title="Lead" />
        <LeadsNotEnabled />
      </div>
    );
  }

  if (leadQuery.isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-9 w-64" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }

  if (leadQuery.isError || !leadQuery.data) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Lead"
          actions={
            <Button variant="outline" onClick={() => navigate("/crm/leads")}>
              <ArrowLeft className="mr-2 h-4 w-4" /> Back
            </Button>
          }
        />
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            Lead not found or you do not have access.
          </CardContent>
        </Card>
      </div>
    );
  }

  const lead = leadQuery.data;
  const isConverted = lead.status === "converted";
  const transitions = LEAD_STATUS_TRANSITIONS[lead.status as LeadStatus] ?? [];
  const canConvert = transitions.includes("converted") && !isConverted;

  return (
    <div className="space-y-6">
      <PageHeader
        title={fullName(lead.first_name, lead.last_name)}
        description={lead.email}
        actions={
          <Button variant="outline" onClick={() => navigate("/crm/leads")}>
            <ArrowLeft className="mr-2 h-4 w-4" /> Back
          </Button>
        }
      />

      {/* Action bar */}
      <Card>
        <CardContent className="flex flex-wrap items-center gap-3 py-4">
          <Badge variant="outline" className={statusVariant(lead.status)}>
            {humanize(lead.status)}
          </Badge>

          {!isConverted && transitions.length > 0 && (
            <Select
              value=""
              onValueChange={(v) => statusMut.mutate(v as LeadStatus)}
            >
              <SelectTrigger className="w-[200px]">
                <SelectValue placeholder="Change status / qualify…" />
              </SelectTrigger>
              <SelectContent>
                {transitions.map((s) => (
                  <SelectItem key={s} value={s}>
                    {humanize(s)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}

          <Button
            variant="outline"
            onClick={() => setAssignDialog(true)}
            disabled={isConverted}
          >
            <UserCheck className="mr-2 h-4 w-4" /> Assign
          </Button>

          <Button onClick={() => setConvertDialog(true)} disabled={!canConvert}>
            <GitMerge className="mr-2 h-4 w-4" /> Convert
          </Button>

          <Button variant="outline" onClick={() => scoreMut.mutate()} disabled={scoreMut.isPending}>
            <Sparkles className="mr-2 h-4 w-4" /> Recompute Score
          </Button>

          <div className="ml-auto flex items-center gap-3">
            <div className="text-right">
              <div className="text-2xl font-semibold tabular-nums">{lead.score}</div>
              <div className="text-xs text-muted-foreground">Lead score</div>
            </div>
            <Button
              variant="ghost"
              size="icon"
              className="text-destructive"
              onClick={() => setDeleteDialog(true)}
              title="Delete lead"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Details */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>Details</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <Field label="Company" value={lead.company} />
            <Field label="Title" value={lead.title} />
            <Field label="Phone" value={lead.phone} />
            <Field label="Website" value={lead.website} />
            <Field label="Source" value={humanize(lead.lead_source)} />
            <Field label="Assigned to" value={lead.assigned_to} />
            <Field label="Campaign" value={lead.campaign_id} />
            <Field label="Attribution" value={lead.attribution_code} />
            <Separator />
            <Field label="Created" value={fmtTs(lead.created_at)} />
            <Field label="Updated" value={fmtTs(lead.updated_at)} />
            {isConverted && (
              <>
                <Separator />
                <Field label="Converted at" value={fmtTs(lead.converted_at)} />
                <Field label="Party ID" value={lead.converted_party_id} />
                <Field label="Org ID" value={lead.converted_org_id} />
              </>
            )}
            {lead.description && (
              <>
                <Separator />
                <div>
                  <div className="text-xs font-medium text-muted-foreground">Description</div>
                  <p className="mt-1 whitespace-pre-wrap">{lead.description}</p>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        {/* Tabs: Activities / Score history */}
        <Card className="lg:col-span-2">
          <CardContent className="pt-6">
            <Tabs defaultValue="activities">
              <TabsList>
                <TabsTrigger value="activities">
                  <ActivityIcon className="mr-1.5 h-4 w-4" /> Activities
                </TabsTrigger>
                <TabsTrigger value="score">
                  <History className="mr-1.5 h-4 w-4" /> Score history
                </TabsTrigger>
              </TabsList>

              <TabsContent value="activities" className="space-y-4 pt-4">
                <div className="space-y-3 rounded-lg border p-3">
                  <div className="flex flex-wrap items-end gap-2">
                    <div className="space-y-1">
                      <Label className="text-xs">Type</Label>
                      <Select value={actType} onValueChange={setActType}>
                        <SelectTrigger className="w-[150px]">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {LEAD_ACTIVITY_TYPES.map((t) => (
                            <SelectItem key={t} value={t}>
                              {humanize(t)}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="flex-1 space-y-1">
                      <Label className="text-xs">Subject</Label>
                      <Input
                        value={actSubject}
                        onChange={(e) => setActSubject(e.target.value)}
                        placeholder="Optional subject"
                      />
                    </div>
                  </div>
                  <Textarea
                    rows={2}
                    value={actDesc}
                    onChange={(e) => setActDesc(e.target.value)}
                    placeholder="Activity notes…"
                  />
                  <div className="flex justify-end">
                    <Button
                      size="sm"
                      onClick={() => activityMut.mutate()}
                      disabled={activityMut.isPending || (!actSubject.trim() && !actDesc.trim())}
                    >
                      Log activity
                    </Button>
                  </div>
                </div>

                {activitiesQuery.isLoading ? (
                  <Skeleton className="h-24 w-full" />
                ) : (activitiesQuery.data?.activities.length ?? 0) === 0 ? (
                  <p className="py-6 text-center text-sm text-muted-foreground">
                    No activities logged yet.
                  </p>
                ) : (
                  <ul className="space-y-2">
                    {activitiesQuery.data!.activities.map((a) => (
                      <li key={a.activity_id} className="rounded-md border p-3 text-sm">
                        <div className="flex items-center justify-between">
                          <Badge variant="secondary">{humanize(a.activity_type)}</Badge>
                          <span className="text-xs text-muted-foreground">
                            {fmtTs(a.created_at)}
                          </span>
                        </div>
                        {a.subject && <div className="mt-1 font-medium">{a.subject}</div>}
                        {a.description && (
                          <p className="mt-0.5 whitespace-pre-wrap text-muted-foreground">
                            {a.description}
                          </p>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </TabsContent>

              <TabsContent value="score" className="pt-4">
                {scoreHistoryQuery.isLoading ? (
                  <Skeleton className="h-24 w-full" />
                ) : (scoreHistoryQuery.data?.entries.length ?? 0) === 0 ? (
                  <p className="py-6 text-center text-sm text-muted-foreground">
                    No score history yet. Use “Recompute Score” to generate an entry.
                  </p>
                ) : (
                  <ul className="space-y-2">
                    {scoreHistoryQuery.data!.entries.map((e, i) => (
                      <li
                        key={`${e.computed_at}-${i}`}
                        className="flex items-center justify-between rounded-md border p-3 text-sm"
                      >
                        <span className="font-medium tabular-nums">{e.score}</span>
                        <span className="text-xs text-muted-foreground">
                          {humanize(e.trigger)}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {fmtTs(e.computed_at)}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>

      {/* Assign dialog */}
      <Dialog open={assignDialog} onOpenChange={setAssignDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Assign lead</DialogTitle>
            <DialogDescription>
              Enter the user identifier (sub) of the person to assign this lead to.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5">
            <Label htmlFor="assignee">Assignee (user sub)</Label>
            <Input
              id="assignee"
              value={assignee}
              onChange={(e) => setAssignee(e.target.value)}
              placeholder="user@example.com"
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAssignDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => assignMut.mutate()}
              disabled={!assignee.trim() || assignMut.isPending}
            >
              Assign
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Convert dialog */}
      <Dialog open={convertDialog} onOpenChange={setConvertDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Convert lead</DialogTitle>
            <DialogDescription>
              Convert this lead into a contact, and optionally create an account and opportunity.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <Checkbox
                id="create_account"
                checked={conv.create_account}
                onCheckedChange={(c) =>
                  setConv((p) => ({ ...p, create_account: c === true }))
                }
              />
              <Label htmlFor="create_account">Create account / organization</Label>
            </div>
            {conv.create_account && (
              <div className="space-y-1.5 pl-6">
                <Label htmlFor="account_name">Account name</Label>
                <Input
                  id="account_name"
                  value={conv.account_name ?? ""}
                  onChange={(e) => setConv((p) => ({ ...p, account_name: e.target.value }))}
                  placeholder={lead.company ?? "Account name"}
                />
              </div>
            )}

            <div className="flex items-center gap-2">
              <Checkbox
                id="create_opp"
                checked={conv.create_opportunity}
                onCheckedChange={(c) =>
                  setConv((p) => ({ ...p, create_opportunity: c === true }))
                }
              />
              <Label htmlFor="create_opp">Create opportunity</Label>
            </div>
            {conv.create_opportunity && (
              <div className="space-y-3 pl-6">
                <div className="space-y-1.5">
                  <Label htmlFor="opp_name">Opportunity name</Label>
                  <Input
                    id="opp_name"
                    value={conv.opportunity_name ?? ""}
                    onChange={(e) =>
                      setConv((p) => ({ ...p, opportunity_name: e.target.value }))
                    }
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="opp_amt">Amount (USD)</Label>
                  <Input
                    id="opp_amt"
                    type="number"
                    min={0}
                    step="0.01"
                    value={
                      conv.opportunity_amount_cents != null
                        ? (conv.opportunity_amount_cents / 100).toString()
                        : ""
                    }
                    onChange={(e) => {
                      const n = parseFloat(e.target.value);
                      setConv((p) => ({
                        ...p,
                        opportunity_amount_cents: isNaN(n) ? undefined : Math.round(n * 100),
                      }));
                    }}
                  />
                  {conv.opportunity_amount_cents != null && (
                    <p className="text-xs text-muted-foreground">
                      {fmtCents(conv.opportunity_amount_cents)}
                    </p>
                  )}
                </div>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConvertDialog(false)}>
              Cancel
            </Button>
            <Button onClick={() => convertMut.mutate()} disabled={convertMut.isPending}>
              {convertMut.isPending ? "Converting…" : "Convert Lead"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirm */}
      <AlertDialog open={deleteDialog} onOpenChange={setDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete this lead?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone. The lead and its history will be removed.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteMut.mutate()}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function Field({ label, value }: { label: string; value?: string | null }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      <span className="text-right">{value || "—"}</span>
    </div>
  );
}
