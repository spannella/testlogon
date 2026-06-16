import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import {
  ArrowLeft,
  CheckCircle2,
  Pencil,
  Trash2,
  Users,
  XCircle,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ApiError } from "@/api/client";
import {
  addContactRole,
  CONTACT_ROLES,
  deleteOpportunity,
  formatCents,
  formatDate,
  getOpportunity,
  isLostStage,
  isWonStage,
  listStages,
  removeContactRole,
  stageLabel,
  updateOpportunity,
  type OppContactRoleIn,
  type OpportunityUpdateIn,
  type StageConfigItemOut,
} from "@/api/endpoints/opportunities";
import { FeatureDisabledState } from "./FeatureDisabledState";
import { OpportunityFormDialog } from "./OpportunityFormDialog";

function stageBadgeVariant(
  stageKey: string,
): "default" | "secondary" | "success" | "destructive" {
  if (isWonStage(stageKey)) return "success";
  if (isLostStage(stageKey)) return "destructive";
  return "secondary";
}

export default function OpportunityDetailPage() {
  const { oppId = "" } = useParams<{ oppId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [editOpen, setEditOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [newStage, setNewStage] = useState<string>("");
  const [contactRef, setContactRef] = useState("");
  const [contactRole, setContactRole] = useState<string>(CONTACT_ROLES[0]);

  const stagesQuery = useQuery({
    queryKey: ["opps", "stages"],
    queryFn: listStages,
    retry: false,
  });

  const oppQuery = useQuery({
    queryKey: ["opps", "detail", oppId],
    queryFn: () => getOpportunity(oppId, true),
    enabled: !!oppId,
    retry: (count, err) =>
      !(err instanceof ApiError && (err.status === 503 || err.status === 404)) &&
      count < 2,
  });

  const stages: StageConfigItemOut[] = stagesQuery.data?.stages ?? [];
  const opp = oppQuery.data;

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["opps", "detail", oppId] });
    queryClient.invalidateQueries({ queryKey: ["opps", "list"] });
  };

  const patchMut = useMutation({
    mutationFn: (body: OpportunityUpdateIn) => updateOpportunity(oppId, body),
    onSuccess: () => {
      toast.success("Opportunity updated");
      setEditOpen(false);
      setNewStage("");
      invalidate();
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Update failed"),
  });

  const deleteMut = useMutation({
    mutationFn: () => deleteOpportunity(oppId),
    onSuccess: () => {
      toast.success("Opportunity deleted");
      queryClient.invalidateQueries({ queryKey: ["opps", "list"] });
      navigate("/crm/opportunities");
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Delete failed"),
  });

  const addRoleMut = useMutation({
    mutationFn: (body: OppContactRoleIn) => addContactRole(oppId, body),
    onSuccess: () => {
      toast.success("Contact added");
      setContactRef("");
      invalidate();
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Failed to add contact"),
  });

  const removeRoleMut = useMutation({
    mutationFn: (ref: string) => removeContactRole(oppId, ref),
    onSuccess: () => {
      toast.success("Contact removed");
      invalidate();
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Failed to remove contact"),
  });

  // ── Loading / error states ──
  if (oppQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-64" />
        <Skeleton className="h-48 w-full" />
      </div>
    );
  }

  if (oppQuery.error instanceof ApiError && oppQuery.error.status === 503) {
    return (
      <div className="space-y-6">
        <Button variant="ghost" size="sm" onClick={() => navigate("/crm/opportunities")}>
          <ArrowLeft className="mr-1.5 h-4 w-4" />
          Back
        </Button>
        <FeatureDisabledState />
      </div>
    );
  }

  if (!opp) {
    return (
      <div className="space-y-6">
        <Button variant="ghost" size="sm" onClick={() => navigate("/crm/opportunities")}>
          <ArrowLeft className="mr-1.5 h-4 w-4" />
          Back
        </Button>
        <Card className="mx-auto max-w-lg">
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            Opportunity not found.
          </CardContent>
        </Card>
      </div>
    );
  }

  const closed = isWonStage(opp.stage) || isLostStage(opp.stage);

  return (
    <div className="space-y-6">
      <Button variant="ghost" size="sm" onClick={() => navigate("/crm/opportunities")}>
        <ArrowLeft className="mr-1.5 h-4 w-4" />
        Back to pipeline
      </Button>

      <PageHeader
        title={opp.name}
        description={`Created ${formatDate(opp.created_at)} · Updated ${formatDate(opp.updated_at)}`}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => setEditOpen(true)}>
              <Pencil className="mr-1.5 h-4 w-4" />
              Edit
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setDeleteOpen(true)}
              data-testid="delete-opp-btn"
            >
              <Trash2 className="mr-1.5 h-4 w-4" />
              Delete
            </Button>
          </div>
        }
      />

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Key metrics */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Badge variant={stageBadgeVariant(opp.stage)}>{stageLabel(opp.stage)}</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <div>
                <p className="text-xs text-muted-foreground">Amount</p>
                <p className="text-lg font-semibold">{formatCents(opp.amount_cents)}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Weighted</p>
                <p className="text-lg font-semibold">
                  {formatCents(opp.weighted_amount_cents)}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Probability</p>
                <p className="text-lg font-semibold">{opp.probability}%</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Close date</p>
                <p className="text-lg font-semibold">{formatDate(opp.close_date)}</p>
              </div>
            </div>

            <div>
              <p className="mb-1 text-xs text-muted-foreground">Win probability</p>
              <Progress value={opp.probability} />
            </div>

            {opp.lead_source && (
              <div>
                <p className="text-xs text-muted-foreground">Lead source</p>
                <p className="text-sm">{opp.lead_source.replace(/_/g, " ")}</p>
              </div>
            )}
            {(opp.account_party_id || opp.contact_party_id) && (
              <div className="grid grid-cols-2 gap-4">
                {opp.account_party_id && (
                  <div>
                    <p className="text-xs text-muted-foreground">Account</p>
                    <p className="text-sm">{opp.account_party_id}</p>
                  </div>
                )}
                {opp.contact_party_id && (
                  <div>
                    <p className="text-xs text-muted-foreground">Primary contact</p>
                    <p className="text-sm">{opp.contact_party_id}</p>
                  </div>
                )}
              </div>
            )}
            {opp.description && (
              <div>
                <p className="text-xs text-muted-foreground">Description</p>
                <p className="whitespace-pre-wrap text-sm">{opp.description}</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Stage transition + close */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Move stage</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {closed ? (
              <Badge
                variant={isWonStage(opp.stage) ? "success" : "destructive"}
                className="w-full justify-center py-1.5"
              >
                {isWonStage(opp.stage) ? "Deal won" : "Deal lost"}
              </Badge>
            ) : null}

            <div className="grid gap-2">
              <Label htmlFor="stage-move">Set stage</Label>
              <Select
                value={newStage || opp.stage}
                onValueChange={(v) => setNewStage(v)}
              >
                <SelectTrigger id="stage-move" data-testid="stage-select">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {stages.map((s) => (
                    <SelectItem key={s.stage_key} value={s.stage_key}>
                      {s.label || stageLabel(s.stage_key)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                size="sm"
                disabled={!newStage || newStage === opp.stage || patchMut.isPending}
                onClick={() => patchMut.mutate({ stage: newStage })}
                data-testid="apply-stage-btn"
              >
                Apply stage
              </Button>
            </div>

            <div className="grid grid-cols-2 gap-2 border-t pt-4">
              <Button
                variant="outline"
                size="sm"
                disabled={isWonStage(opp.stage) || patchMut.isPending}
                onClick={() =>
                  patchMut.mutate({ stage: "closed_won", probability: 100 })
                }
                data-testid="close-won-btn"
              >
                <CheckCircle2 className="mr-1.5 h-4 w-4" />
                Close won
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={isLostStage(opp.stage) || patchMut.isPending}
                onClick={() =>
                  patchMut.mutate({ stage: "closed_lost", probability: 0 })
                }
                data-testid="close-lost-btn"
              >
                <XCircle className="mr-1.5 h-4 w-4" />
                Close lost
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Contact roles */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Users className="h-4 w-4" />
            Contact roles
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {opp.contact_roles.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No contacts linked to this opportunity yet.
            </p>
          ) : (
            <div className="divide-y rounded-md border">
              {opp.contact_roles.map((cr) => (
                <div
                  key={cr.contact_ref}
                  className="flex items-center justify-between px-3 py-2"
                  data-testid="contact-role-row"
                >
                  <div>
                    <p className="text-sm font-medium">{cr.contact_ref}</p>
                    <p className="text-xs text-muted-foreground">
                      {cr.contact_role.replace(/_/g, " ")}
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => removeRoleMut.mutate(cr.contact_ref)}
                    disabled={removeRoleMut.isPending}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </div>
          )}

          <div className="flex flex-wrap items-end gap-2 border-t pt-4">
            <div className="grid gap-1.5">
              <Label htmlFor="contact-ref">Contact reference</Label>
              <Input
                id="contact-ref"
                className="w-56"
                value={contactRef}
                onChange={(e) => setContactRef(e.target.value)}
                placeholder="contact id / email"
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="contact-role">Role</Label>
              <Select value={contactRole} onValueChange={setContactRole}>
                <SelectTrigger id="contact-role" className="w-48">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CONTACT_ROLES.map((r) => (
                    <SelectItem key={r} value={r}>
                      {r.replace(/_/g, " ")}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button
              size="sm"
              disabled={!contactRef.trim() || addRoleMut.isPending}
              onClick={() =>
                addRoleMut.mutate({
                  contact_ref: contactRef.trim(),
                  contact_role: contactRole,
                })
              }
              data-testid="add-contact-btn"
            >
              Add contact
            </Button>
          </div>
        </CardContent>
      </Card>

      <OpportunityFormDialog
        open={editOpen}
        onOpenChange={setEditOpen}
        stages={stages}
        existing={opp}
        onSubmit={(body) => patchMut.mutate(body)}
        saving={patchMut.isPending}
      />

      <AlertDialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete opportunity?</AlertDialogTitle>
            <AlertDialogDescription>
              This permanently removes "{opp.name}" and its contact roles. This cannot
              be undone.
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
