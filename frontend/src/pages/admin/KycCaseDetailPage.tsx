import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ArrowLeft,
  CheckCircle,
  XCircle,
  MessageSquare,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { DocumentViewer } from "@/components/shared/DocumentViewer";
import { ExtractionResultsPanel } from "@/components/shared/ExtractionResultsPanel";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  fetchKycCaseDetail,
  approveKycCase,
  rejectKycCase,
  requestKycInfo,
  type KycCaseDetail,
  type KycTimelineEvent,
} from "@/api/endpoints/kyc-admin";
import { KycFacialComparisonReview } from "@/pages/admin/KycFacialComparisonReview";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatDate(ts: number | null): string {
  if (!ts) return "--";
  return new Date(ts * 1000).toLocaleString();
}

function statusBadgeVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "submitted":
      return "default";
    case "under_review":
      return "secondary";
    case "needs_more_info":
      return "outline";
    case "approved":
      return "default";
    case "rejected":
      return "destructive";
    default:
      return "secondary";
  }
}

const APPROVE_REASON_CODES = [
  { value: "identity_verified", label: "Identity Verified" },
  { value: "documents_valid", label: "Documents Valid" },
  { value: "face_match_confirmed", label: "Face Match Confirmed" },
  { value: "address_confirmed", label: "Address Confirmed" },
];

const REJECT_REASON_CODES = [
  { value: "document_illegible", label: "Document Illegible" },
  { value: "name_mismatch", label: "Name Mismatch" },
  { value: "expired_document", label: "Expired Document" },
  { value: "suspected_fraud", label: "Suspected Fraud" },
  { value: "face_mismatch", label: "Face Mismatch" },
  { value: "incomplete_submission", label: "Incomplete Submission" },
];

const REQUEST_INFO_ITEMS = [
  { value: "selfie", label: "Selfie Photo" },
  { value: "id_front", label: "ID Front" },
  { value: "id_back", label: "ID Back" },
  { value: "proof_of_address", label: "Proof of Address" },
];

// ─── Timeline ─────────────────────────────────────────────────────────────────

function CaseTimeline({ events }: { events: KycTimelineEvent[] }) {
  const sorted = [...events].sort((a, b) => (a.created_at ?? 0) - (b.created_at ?? 0));

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">Timeline</CardTitle>
      </CardHeader>
      <CardContent>
        {sorted.length === 0 ? (
          <p className="text-sm text-muted-foreground">No timeline events.</p>
        ) : (
          <ol className="relative border-l border-muted-foreground/20 space-y-4 ml-2">
            {sorted.map((ev, i) => (
              <li key={i} className="ml-4" data-testid="timeline-event">
                <div className="absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full border border-background bg-muted-foreground/40" />
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span>{formatDate(ev.created_at)}</span>
                  <span>|</span>
                  <span>{ev.actor_sub ?? "system"}</span>
                </div>
                <p className="text-sm font-medium" data-testid="timeline-event-type">
                  {ev.event_type}
                </p>
                {Object.keys(ev.details).length > 0 && (
                  <pre className="mt-1 text-xs text-muted-foreground bg-muted rounded px-2 py-1 overflow-auto max-h-24">
                    {JSON.stringify(ev.details, null, 2)}
                  </pre>
                )}
              </li>
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function KycCaseDetailPage() {
  const { caseId } = useParams<{ caseId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [approveDialogOpen, setApproveDialogOpen] = useState(false);
  const [rejectDialogOpen, setRejectDialogOpen] = useState(false);
  const [requestInfoDialogOpen, setRequestInfoDialogOpen] = useState(false);

  const [selectedReasonCodes, setSelectedReasonCodes] = useState<string[]>([]);
  const [actionNote, setActionNote] = useState("");
  const [selectedRequestItems, setSelectedRequestItems] = useState<string[]>([]);

  const caseQuery = useQuery({
    queryKey: ["kyc-case", caseId],
    queryFn: () => fetchKycCaseDetail(caseId!),
    enabled: !!caseId,
  });

  const caseData: KycCaseDetail | undefined = caseQuery.data?.case;

  // Extract version from timeline's kyc_case_updated event details
  // (admin detail response doesn't include version at top level)
  const caseVersion: number = (() => {
    if (!caseData) return 1;
    const updatedEvent = caseData.timeline.find((e) => e.event_type === "kyc_case_updated");
    const v = (updatedEvent?.details as Record<string, unknown>)?.version;
    return typeof v === "number" ? v : 1;
  })();

  const approveMut = useMutation({
    mutationFn: () =>
      approveKycCase(caseId!, {
        expected_version: caseVersion ?? 1,
        reason_codes: selectedReasonCodes,
        note: actionNote,
      }),
    onSuccess: () => {
      toast.success("Case approved successfully.");
      queryClient.invalidateQueries({ queryKey: ["kyc-case", caseId] });
      queryClient.invalidateQueries({ queryKey: ["kyc-queue"] });
      setApproveDialogOpen(false);
      resetForm();
    },
    onError: (err: unknown) => {
      const body = (err as any)?.body;
      const errorCode = body?.detail?.error?.code ?? body?.error?.code;
      if (errorCode === "kyc_case_update_conflict") {
        toast.error("This case was modified by another reviewer. Please refresh.");
        queryClient.invalidateQueries({ queryKey: ["kyc-case", caseId] });
      } else {
        toast.error("Failed to approve case.");
      }
    },
  });

  const rejectMut = useMutation({
    mutationFn: () =>
      rejectKycCase(caseId!, {
        expected_version: caseVersion ?? 1,
        reason_codes: selectedReasonCodes,
        note: actionNote,
      }),
    onSuccess: () => {
      toast.success("Case rejected.");
      queryClient.invalidateQueries({ queryKey: ["kyc-case", caseId] });
      queryClient.invalidateQueries({ queryKey: ["kyc-queue"] });
      setRejectDialogOpen(false);
      resetForm();
    },
    onError: (err: unknown) => {
      const body = (err as any)?.body;
      const errorCode = body?.detail?.error?.code ?? body?.error?.code;
      if (errorCode === "kyc_case_update_conflict") {
        toast.error("This case was modified by another reviewer. Please refresh.");
        queryClient.invalidateQueries({ queryKey: ["kyc-case", caseId] });
      } else {
        toast.error("Failed to reject case.");
      }
    },
  });

  const requestInfoMut = useMutation({
    mutationFn: () =>
      requestKycInfo(caseId!, {
        expected_version: caseVersion ?? 1,
        requested_items: selectedRequestItems,
        note: actionNote,
      }),
    onSuccess: () => {
      toast.success("More information requested.");
      queryClient.invalidateQueries({ queryKey: ["kyc-case", caseId] });
      queryClient.invalidateQueries({ queryKey: ["kyc-queue"] });
      setRequestInfoDialogOpen(false);
      resetForm();
    },
    onError: () => {
      toast.error("Failed to request information.");
    },
  });

  function resetForm() {
    setSelectedReasonCodes([]);
    setActionNote("");
    setSelectedRequestItems([]);
  }

  function toggleReasonCode(code: string) {
    setSelectedReasonCodes((prev) =>
      prev.includes(code) ? prev.filter((c) => c !== code) : [...prev, code],
    );
  }

  function toggleRequestItem(item: string) {
    setSelectedRequestItems((prev) =>
      prev.includes(item) ? prev.filter((i) => i !== item) : [...prev, item],
    );
  }

  if (caseQuery.isLoading) {
    return (
      <div className="container mx-auto max-w-6xl px-4 py-6">
        <p className="text-muted-foreground">Loading case detail...</p>
      </div>
    );
  }

  if (!caseData) {
    return (
      <div className="container mx-auto max-w-6xl px-4 py-6">
        <p className="text-muted-foreground">Case not found.</p>
      </div>
    );
  }

  const isActionable = ["submitted", "under_review", "needs_more_info"].includes(caseData.status);

  return (
    <div className="container mx-auto max-w-7xl space-y-6 px-4 py-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="sm" onClick={() => navigate("/admin/kyc")}>
          <ArrowLeft className="mr-1 h-4 w-4" />
          Back to Queue
        </Button>
      </div>

      <div className="flex items-center gap-3">
        <PageHeader
          title={`Case: ${caseData.kyc_case_id}`}
        />
        <Badge variant={statusBadgeVariant(caseData.status)} className="text-sm" data-testid="case-status-badge">
          {caseData.status}
        </Badge>
      </div>

      <Tabs defaultValue="overview" className="w-full">
        <TabsList>
          <TabsTrigger value="overview" data-testid="tab-overview">
            Overview
          </TabsTrigger>
          <TabsTrigger value="extraction" data-testid="tab-extraction">
            Document Extraction
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
      {/* Two-column layout */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
        {/* Left: Document Viewer (60%) */}
        <div className="lg:col-span-3 space-y-6">
          <DocumentViewer files={caseData.files_ref} />
          <KycFacialComparisonReview caseId={caseData.kyc_case_id} />
        </div>

        {/* Right: Info + Actions (40%) */}
        <div className="lg:col-span-2 space-y-6">
          {/* Case Info */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">Case Information</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">User</span>
                <span data-testid="case-user-sub">{caseData.user_sub}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Status</span>
                <Badge variant={statusBadgeVariant(caseData.status)}>{caseData.status}</Badge>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Questionnaire</span>
                <span>
                  {caseData.questionnaire_ref?.questionnaire_id ? "Linked" : "Not linked"}
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Signature</span>
                <span>
                  {(caseData.signature_ref as Record<string, unknown>)?.packet_id
                    ? String((caseData.signature_ref as Record<string, unknown>).status ?? "pending")
                    : "Not linked"}
                </span>
              </div>
              {caseData.decision_state?.decision && (
                <>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Decision</span>
                    <span className="capitalize">{caseData.decision_state.decision}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Decided At</span>
                    <span>{formatDate(caseData.decision_state.decided_at)}</span>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          {/* Actions */}
          {isActionable && (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm font-medium">Actions</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-wrap gap-2">
                <Button
                  onClick={() => {
                    resetForm();
                    setApproveDialogOpen(true);
                  }}
                  className="bg-green-600 hover:bg-green-700"
                >
                  <CheckCircle className="mr-1 h-4 w-4" />
                  Approve
                </Button>
                <Button
                  variant="destructive"
                  onClick={() => {
                    resetForm();
                    setRejectDialogOpen(true);
                  }}
                >
                  <XCircle className="mr-1 h-4 w-4" />
                  Reject
                </Button>
                <Button
                  variant="outline"
                  onClick={() => {
                    resetForm();
                    setRequestInfoDialogOpen(true);
                  }}
                >
                  <MessageSquare className="mr-1 h-4 w-4" />
                  Request Info
                </Button>
              </CardContent>
            </Card>
          )}

          {/* Timeline */}
          <CaseTimeline events={caseData.timeline} />
        </div>
      </div>
        </TabsContent>

        <TabsContent value="extraction">
          <ExtractionResultsPanel caseId={caseData.kyc_case_id} />
        </TabsContent>
      </Tabs>

      {/* Approve Dialog */}
      <Dialog open={approveDialogOpen} onOpenChange={setApproveDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Approve Case</DialogTitle>
            <DialogDescription>
              Select reason codes and add a note to approve this KYC case.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Reason Codes</Label>
              <div className="mt-2 space-y-2">
                {APPROVE_REASON_CODES.map((rc) => (
                  <div key={rc.value} className="flex items-center gap-2">
                    <Checkbox
                      id={`approve-rc-${rc.value}`}
                      checked={selectedReasonCodes.includes(rc.value)}
                      onCheckedChange={() => toggleReasonCode(rc.value)}
                    />
                    <Label htmlFor={`approve-rc-${rc.value}`} className="text-sm font-normal">
                      {rc.label}
                    </Label>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <Label htmlFor="approve-note">Notes</Label>
              <Textarea
                id="approve-note"
                placeholder="Add review notes..."
                value={actionNote}
                onChange={(e) => setActionNote(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setApproveDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => approveMut.mutate()}
              disabled={selectedReasonCodes.length === 0 || actionNote.trim().length < 5 || approveMut.isPending}
              className="bg-green-600 hover:bg-green-700"
            >
              {approveMut.isPending ? "Approving..." : "Confirm Approval"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Reject Dialog */}
      <Dialog open={rejectDialogOpen} onOpenChange={setRejectDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reject Case</DialogTitle>
            <DialogDescription>
              Select reason codes and add a note explaining the rejection.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Reason Codes</Label>
              <div className="mt-2 space-y-2">
                {REJECT_REASON_CODES.map((rc) => (
                  <div key={rc.value} className="flex items-center gap-2">
                    <Checkbox
                      id={`reject-rc-${rc.value}`}
                      checked={selectedReasonCodes.includes(rc.value)}
                      onCheckedChange={() => toggleReasonCode(rc.value)}
                    />
                    <Label htmlFor={`reject-rc-${rc.value}`} className="text-sm font-normal">
                      {rc.label}
                    </Label>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <Label htmlFor="reject-note">Notes</Label>
              <Textarea
                id="reject-note"
                placeholder="Add rejection reason..."
                value={actionNote}
                onChange={(e) => setActionNote(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRejectDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => rejectMut.mutate()}
              disabled={selectedReasonCodes.length === 0 || actionNote.trim().length < 5 || rejectMut.isPending}
            >
              {rejectMut.isPending ? "Rejecting..." : "Confirm Rejection"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Request Info Dialog */}
      <Dialog open={requestInfoDialogOpen} onOpenChange={setRequestInfoDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Request More Information</DialogTitle>
            <DialogDescription>
              Select which documents the applicant needs to provide and add a note.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Requested Items</Label>
              <div className="mt-2 space-y-2">
                {REQUEST_INFO_ITEMS.map((item) => (
                  <div key={item.value} className="flex items-center gap-2">
                    <Checkbox
                      id={`req-item-${item.value}`}
                      checked={selectedRequestItems.includes(item.value)}
                      onCheckedChange={() => toggleRequestItem(item.value)}
                    />
                    <Label htmlFor={`req-item-${item.value}`} className="text-sm font-normal">
                      {item.label}
                    </Label>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <Label htmlFor="request-info-note">Notes</Label>
              <Textarea
                id="request-info-note"
                placeholder="Explain what additional information is needed..."
                value={actionNote}
                onChange={(e) => setActionNote(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRequestInfoDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => requestInfoMut.mutate()}
              disabled={selectedRequestItems.length === 0 || actionNote.trim().length < 1 || requestInfoMut.isPending}
            >
              {requestInfoMut.isPending ? "Sending..." : "Send Request"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
