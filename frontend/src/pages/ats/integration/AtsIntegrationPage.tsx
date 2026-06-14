/**
 * ATI — ATS Integration cross-link bridge UI (ATI-001..ATI-005).
 *
 * Route: /ats/integration
 *
 * Shows two panels:
 *   1. Candidate <-> Contact Links  (ATI-001/ATI-004)
 *   2. Job Order <-> Opportunity Links  (ATI-002/ATI-005)
 *
 * When the backend gate is off (503) both panels render a "not enabled" callout
 * rather than an error state. The panels also surface a "degraded" badge when
 * a sibling cluster was unreachable at link-creation time — this is the normal
 * cross-cluster degrade described in ATI-003.
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { AlertTriangle, GitMerge, Link2, Plus, RefreshCw, Trash2, Unlink } from "lucide-react";

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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import { ApiError } from "@/api/client";
import {
  createCandidateContactLink,
  createJobOpportunityLink,
  deleteIntegrationLink,
  listIntegrationLinks,
  type CandidateContactLink,
  type JobOpportunityLink,
} from "@/api/endpoints/atsIntegration";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmt(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function DegradedBadge({ reason }: { reason: string | null }) {
  if (!reason) return null;
  const reasons = reason.split(",").filter(Boolean);
  return (
    <span className="flex items-center gap-1 flex-wrap">
      <Badge variant="destructive" className="text-xs gap-1">
        <AlertTriangle className="h-3 w-3" />
        Degraded
      </Badge>
      {reasons.map((r) => (
        <Badge key={r} variant="outline" className="text-xs font-mono">
          {r}
        </Badge>
      ))}
    </span>
  );
}

function SyncBadge({ synced }: { synced: boolean }) {
  return synced ? (
    <Badge variant="secondary" className="text-xs">Synced</Badge>
  ) : (
    <Badge variant="outline" className="text-xs">Not synced</Badge>
  );
}

// ─── Not-enabled state ────────────────────────────────────────────────────────

function NotEnabledState() {
  return (
    <Card>
      <CardContent className="pt-8 pb-8 text-center">
        <Unlink className="mx-auto h-10 w-10 text-muted-foreground mb-3" />
        <p className="text-muted-foreground text-sm font-medium">
          ATS Integration is not enabled.
        </p>
        <p className="text-muted-foreground text-xs mt-1">
          Set <code className="bg-muted px-1 rounded">ATS_INTEGRATION_ENABLED=true</code> and{" "}
          <code className="bg-muted px-1 rounded">CANDIDATES_ENABLED=true</code> to activate the
          cross-link bridge.
        </p>
      </CardContent>
    </Card>
  );
}

// ─── Candidate-Contact links panel ───────────────────────────────────────────

interface CreateCCLinkDialogProps {
  onSuccess: () => void;
}

function CreateCCLinkDialog({ onSuccess }: CreateCCLinkDialogProps) {
  const [open, setOpen] = useState(false);
  const [candidateId, setCandidateId] = useState("");
  const [contactId, setContactId] = useState("");

  const mut = useMutation({
    mutationFn: () =>
      createCandidateContactLink({
        candidate_id: candidateId.trim(),
        contact_id: contactId.trim() || undefined,
      }),
    onSuccess: (data) => {
      if (data.degraded) {
        toast.warning(
          `Link saved in degraded state: ${data.degraded_reason ?? "sibling cluster unavailable"}`,
        );
      } else {
        toast.success("Candidate linked to contact successfully.");
      }
      setOpen(false);
      setCandidateId("");
      setContactId("");
      onSuccess();
    },
    onError: (err: unknown) => {
      const msg =
        err instanceof ApiError ? err.detail : "Failed to create link.";
      toast.error(msg);
    },
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" className="gap-1">
          <Plus className="h-4 w-4" />
          Link Candidate
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Link Candidate to CRM Contact</DialogTitle>
          <DialogDescription>
            Enter the ATS Candidate ID and optionally a CRM Contact ID. Leave the
            Contact ID blank to auto-create a contact from the candidate (when the
            contacts cluster is enabled).
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid gap-1.5">
            <Label htmlFor="cc-candidate-id">Candidate ID *</Label>
            <Input
              id="cc-candidate-id"
              placeholder="e.g. cand_abc123"
              value={candidateId}
              onChange={(e) => setCandidateId(e.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="cc-contact-id">Contact ID (optional)</Label>
            <Input
              id="cc-contact-id"
              placeholder="e.g. contact_xyz789 — leave blank to auto-sync"
              value={contactId}
              onChange={(e) => setContactId(e.target.value)}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => mut.mutate()}
            disabled={!candidateId.trim() || mut.isPending}
          >
            {mut.isPending ? "Linking…" : "Create Link"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

interface CCLinkRowProps {
  link: CandidateContactLink;
  onDelete: (link: CandidateContactLink) => void;
  isDeleting: boolean;
}

function CCLinkRow({ link, onDelete, isDeleting }: CCLinkRowProps) {
  return (
    <div className="flex items-start gap-3 py-3 border-b last:border-0">
      <GitMerge className="h-4 w-4 mt-0.5 shrink-0 text-muted-foreground" />
      <div className="flex-1 min-w-0 grid gap-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm font-medium font-mono truncate">{link.candidate_id}</span>
          <Link2 className="h-3 w-3 text-muted-foreground shrink-0" />
          <span className="text-sm font-mono truncate text-muted-foreground">
            {link.contact_id || <em className="not-italic text-muted-foreground/60">no contact yet</em>}
          </span>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <SyncBadge synced={link.synced} />
          {link.degraded && <DegradedBadge reason={link.degraded_reason} />}
          <span className="text-xs text-muted-foreground ml-auto">
            Created {fmt(link.created_at)}
          </span>
        </div>
        <p className="text-xs text-muted-foreground font-mono break-all">
          link_id: {link.link_id}
        </p>
      </div>
      <Button
        variant="ghost"
        size="icon"
        className="h-7 w-7 shrink-0 text-destructive hover:text-destructive"
        disabled={isDeleting}
        onClick={() => onDelete(link)}
        aria-label="Unlink"
      >
        <Trash2 className="h-4 w-4" />
      </Button>
    </div>
  );
}

// ─── Job-Opportunity links panel ──────────────────────────────────────────────

interface CreateJOLinkDialogProps {
  onSuccess: () => void;
}

function CreateJOLinkDialog({ onSuccess }: CreateJOLinkDialogProps) {
  const [open, setOpen] = useState(false);
  const [jobOrderId, setJobOrderId] = useState("");
  const [opportunityId, setOpportunityId] = useState("");

  const mut = useMutation({
    mutationFn: () =>
      createJobOpportunityLink({
        job_order_id: jobOrderId.trim(),
        opportunity_id: opportunityId.trim() || undefined,
      }),
    onSuccess: (data) => {
      if (data.degraded) {
        toast.warning(
          `Link saved in degraded state: ${data.degraded_reason ?? "sibling cluster unavailable"}`,
        );
      } else {
        toast.success("Job order linked to opportunity successfully.");
      }
      setOpen(false);
      setJobOrderId("");
      setOpportunityId("");
      onSuccess();
    },
    onError: (err: unknown) => {
      const msg =
        err instanceof ApiError ? err.detail : "Failed to create link.";
      toast.error(msg);
    },
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" className="gap-1">
          <Plus className="h-4 w-4" />
          Link Job Order
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Link Job Order to CRM Opportunity</DialogTitle>
          <DialogDescription>
            Enter the ATS Job Order ID and optionally a CRM Opportunity ID. Leave the
            Opportunity ID blank to auto-create an opportunity from the job order (when
            the opportunities cluster is enabled).
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid gap-1.5">
            <Label htmlFor="jo-job-order-id">Job Order ID *</Label>
            <Input
              id="jo-job-order-id"
              placeholder="e.g. job_abc123"
              value={jobOrderId}
              onChange={(e) => setJobOrderId(e.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="jo-opportunity-id">Opportunity ID (optional)</Label>
            <Input
              id="jo-opportunity-id"
              placeholder="e.g. opp_xyz789 — leave blank to auto-sync"
              value={opportunityId}
              onChange={(e) => setOpportunityId(e.target.value)}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => mut.mutate()}
            disabled={!jobOrderId.trim() || mut.isPending}
          >
            {mut.isPending ? "Linking…" : "Create Link"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

interface JOLinkRowProps {
  link: JobOpportunityLink;
  onDelete: (link: JobOpportunityLink) => void;
  isDeleting: boolean;
}

function JOLinkRow({ link, onDelete, isDeleting }: JOLinkRowProps) {
  return (
    <div className="flex items-start gap-3 py-3 border-b last:border-0">
      <GitMerge className="h-4 w-4 mt-0.5 shrink-0 text-muted-foreground" />
      <div className="flex-1 min-w-0 grid gap-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm font-medium font-mono truncate">{link.job_order_id}</span>
          <Link2 className="h-3 w-3 text-muted-foreground shrink-0" />
          <span className="text-sm font-mono truncate text-muted-foreground">
            {link.opportunity_id || <em className="not-italic text-muted-foreground/60">no opportunity yet</em>}
          </span>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <SyncBadge synced={link.synced} />
          {link.degraded && <DegradedBadge reason={link.degraded_reason} />}
          <span className="text-xs text-muted-foreground ml-auto">
            Created {fmt(link.created_at)}
          </span>
        </div>
        <p className="text-xs text-muted-foreground font-mono break-all">
          link_id: {link.link_id}
        </p>
      </div>
      <Button
        variant="ghost"
        size="icon"
        className="h-7 w-7 shrink-0 text-destructive hover:text-destructive"
        disabled={isDeleting}
        onClick={() => onDelete(link)}
        aria-label="Unlink"
      >
        <Trash2 className="h-4 w-4" />
      </Button>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function AtsIntegrationPage() {
  const qc = useQueryClient();

  const linksQuery = useQuery({
    queryKey: ["ats", "integration", "links"],
    queryFn: listIntegrationLinks,
    retry: (count, err) => {
      // Don't retry on 503 (feature disabled)
      if (err instanceof ApiError && err.status === 503) return false;
      return count < 2;
    },
  });

  const isDisabled =
    linksQuery.isError &&
    linksQuery.error instanceof ApiError &&
    linksQuery.error.status === 503;

  const deleteMut = useMutation({
    mutationFn: ({ linkType, linkId }: { linkType: string; linkId: string }) =>
      deleteIntegrationLink(linkType, linkId),
    onSuccess: () => {
      toast.success("Link removed.");
      qc.invalidateQueries({ queryKey: ["ats", "integration", "links"] });
    },
    onError: (err: unknown) => {
      const msg = err instanceof ApiError ? err.detail : "Failed to remove link.";
      toast.error(msg);
    },
  });

  function handleDeleteCC(link: CandidateContactLink) {
    if (!confirm(`Remove candidate-contact link for candidate "${link.candidate_id}"?`)) return;
    deleteMut.mutate({ linkType: link.link_type, linkId: link.link_id });
  }

  function handleDeleteJO(link: JobOpportunityLink) {
    if (!confirm(`Remove job-opportunity link for job order "${link.job_order_id}"?`)) return;
    deleteMut.mutate({ linkType: link.link_type, linkId: link.link_id });
  }

  function invalidateLinks() {
    qc.invalidateQueries({ queryKey: ["ats", "integration", "links"] });
  }

  const ccLinks = linksQuery.data?.candidate_contact_links ?? [];
  const joLinks = linksQuery.data?.job_opportunity_links ?? [];
  const totalCount = linksQuery.data?.count ?? 0;

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <PageHeader
        title="ATS Integration"
        description="Manage cross-links between the ATS (candidates, job orders) and the CRM (contacts, opportunities)."
        actions={
          <Button
            variant="outline"
            size="sm"
            className="gap-1"
            onClick={invalidateLinks}
            disabled={linksQuery.isFetching}
          >
            <RefreshCw className={`h-4 w-4 ${linksQuery.isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        }
      />

      {isDisabled ? (
        <NotEnabledState />
      ) : (
        <>
          {/* Summary banner */}
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Link2 className="h-4 w-4" />
            {linksQuery.isLoading ? (
              <span>Loading links…</span>
            ) : (
              <span>
                {totalCount} total cross-link{totalCount !== 1 ? "s" : ""}
                {" — "}
                {ccLinks.length} candidate-contact,{" "}
                {joLinks.length} job-opportunity
              </span>
            )}
          </div>

          <Tabs defaultValue="candidate-contact">
            <TabsList>
              <TabsTrigger value="candidate-contact">
                Candidate ↔ Contact
                {ccLinks.length > 0 && (
                  <Badge variant="secondary" className="ml-2 text-xs">
                    {ccLinks.length}
                  </Badge>
                )}
              </TabsTrigger>
              <TabsTrigger value="job-opportunity">
                Job Order ↔ Opportunity
                {joLinks.length > 0 && (
                  <Badge variant="secondary" className="ml-2 text-xs">
                    {joLinks.length}
                  </Badge>
                )}
              </TabsTrigger>
            </TabsList>

            {/* ── Candidate <-> Contact tab ── */}
            <TabsContent value="candidate-contact" className="mt-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between pb-3">
                  <div>
                    <CardTitle className="text-base">Candidate → Contact Links</CardTitle>
                    <CardDescription className="text-xs mt-0.5">
                      ATS candidates linked to CRM contacts. Degraded links were saved when
                      a sibling cluster was unavailable at sync time.
                    </CardDescription>
                  </div>
                  <CreateCCLinkDialog onSuccess={invalidateLinks} />
                </CardHeader>
                <CardContent>
                  {linksQuery.isLoading && (
                    <p className="text-sm text-muted-foreground py-4 text-center">Loading…</p>
                  )}
                  {!linksQuery.isLoading && ccLinks.length === 0 && (
                    <div className="py-8 text-center">
                      <GitMerge className="mx-auto h-8 w-8 text-muted-foreground mb-2" />
                      <p className="text-sm text-muted-foreground">No candidate-contact links yet.</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        Use the button above to create the first ATS cross-link.
                      </p>
                    </div>
                  )}
                  {ccLinks.map((link) => (
                    <CCLinkRow
                      key={link.link_id}
                      link={link}
                      onDelete={handleDeleteCC}
                      isDeleting={
                        deleteMut.isPending &&
                        (deleteMut.variables as { linkId: string }).linkId === link.link_id
                      }
                    />
                  ))}
                </CardContent>
              </Card>
            </TabsContent>

            {/* ── Job Order <-> Opportunity tab ── */}
            <TabsContent value="job-opportunity" className="mt-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between pb-3">
                  <div>
                    <CardTitle className="text-base">Job Order → Opportunity Links</CardTitle>
                    <CardDescription className="text-xs mt-0.5">
                      ATS job orders linked to CRM opportunities. Degraded links were saved when
                      a sibling cluster was unavailable at sync time.
                    </CardDescription>
                  </div>
                  <CreateJOLinkDialog onSuccess={invalidateLinks} />
                </CardHeader>
                <CardContent>
                  {linksQuery.isLoading && (
                    <p className="text-sm text-muted-foreground py-4 text-center">Loading…</p>
                  )}
                  {!linksQuery.isLoading && joLinks.length === 0 && (
                    <div className="py-8 text-center">
                      <GitMerge className="mx-auto h-8 w-8 text-muted-foreground mb-2" />
                      <p className="text-sm text-muted-foreground">No job-opportunity links yet.</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        Use the button above to create the first ATS cross-link.
                      </p>
                    </div>
                  )}
                  {joLinks.map((link) => (
                    <JOLinkRow
                      key={link.link_id}
                      link={link}
                      onDelete={handleDeleteJO}
                      isDeleting={
                        deleteMut.isPending &&
                        (deleteMut.variables as { linkId: string }).linkId === link.link_id
                      }
                    />
                  ))}
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </>
      )}
    </div>
  );
}
