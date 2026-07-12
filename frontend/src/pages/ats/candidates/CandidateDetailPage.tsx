import { useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import {
  ArrowLeft,
  Trash2,
  Edit2,
  Save,
  X,
  Upload,
  Star,
  Download,
  FileText,
  History,
  User,
  Linkedin,
  Globe,
  MapPin,
  Phone,
  Mail,
  Building2,
  Briefcase,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
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
  getCandidate,
  updateCandidate,
  deleteCandidate,
  uploadResume,
  listResumes,
  setPrimaryResume,
  deleteResume,
  getCandidateHistory,
  CANDIDATE_STATUSES,
  CANDIDATE_SOURCES,
  type Candidate,
  type CandidateUpdateIn,
  type CandidateResumeOut,
} from "@/api/endpoints/candidates";
import { CandidatesNotEnabled } from "./CandidatesNotEnabled";
import {
  fmtTs,
  humanize,
  statusColor,
  isNotEnabled,
  fullName,
  formatFileSize,
} from "./candidateUtils";

// ─── Resume list sub-component ────────────────────────────────────────────────

function ResumeSection({
  candidateId,
  primaryResumeId,
}: {
  candidateId: string;
  primaryResumeId?: string | null;
}) {
  const qc = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);

  const resumeQuery = useQuery({
    queryKey: ["ats-candidate-resumes", candidateId],
    queryFn: () => listResumes(candidateId),
    retry: false,
  });

  const uploadMut = useMutation({
    mutationFn: ({ file, primary }: { file: File; primary: boolean }) =>
      uploadResume(candidateId, file, primary),
    onSuccess: () => {
      toast.success("Resume uploaded");
      void qc.invalidateQueries({ queryKey: ["ats-candidate-resumes", candidateId] });
      void qc.invalidateQueries({ queryKey: ["ats-candidate", candidateId] });
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Upload failed"),
  });

  const setPrimaryMut = useMutation({
    mutationFn: (attId: string) => setPrimaryResume(candidateId, attId),
    onSuccess: () => {
      toast.success("Primary resume updated");
      void qc.invalidateQueries({ queryKey: ["ats-candidate-resumes", candidateId] });
      void qc.invalidateQueries({ queryKey: ["ats-candidate", candidateId] });
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Failed to set primary"),
  });

  const deleteMut = useMutation({
    mutationFn: (attId: string) => deleteResume(candidateId, attId),
    onSuccess: () => {
      toast.success("Resume deleted");
      void qc.invalidateQueries({ queryKey: ["ats-candidate-resumes", candidateId] });
      void qc.invalidateQueries({ queryKey: ["ats-candidate", candidateId] });
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Failed to delete resume"),
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const isPrimary = (resumeQuery.data ?? []).length === 0;
    uploadMut.mutate({ file, primary: isPrimary });
    e.target.value = "";
  };

  const resumes: CandidateResumeOut[] = resumeQuery.data ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {resumes.length} resume{resumes.length !== 1 ? "s" : ""} attached
        </p>
        <div>
          <input
            ref={fileRef}
            type="file"
            className="hidden"
            accept=".pdf,.doc,.docx,.rtf,.txt,.odt"
            onChange={handleFileChange}
          />
          <Button
            size="sm"
            variant="outline"
            onClick={() => fileRef.current?.click()}
            disabled={uploadMut.isPending}
          >
            <Upload className="mr-2 h-3.5 w-3.5" />
            {uploadMut.isPending ? "Uploading…" : "Upload resume"}
          </Button>
        </div>
      </div>

      {resumeQuery.isPending ? (
        <div className="space-y-2">
          {[1, 2].map((i) => (
            <Skeleton key={i} className="h-14 w-full" />
          ))}
        </div>
      ) : resumes.length === 0 ? (
        <div className="rounded-lg border border-dashed p-8 text-center">
          <FileText className="mx-auto h-8 w-8 text-muted-foreground" />
          <p className="mt-2 text-sm text-muted-foreground">
            No resumes uploaded yet. Click "Upload resume" to add one.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {resumes.map((r) => (
            <div
              key={r.attachment_id}
              className="flex items-center gap-3 rounded-lg border p-3"
            >
              <FileText className="h-5 w-5 shrink-0 text-muted-foreground" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="truncate text-sm font-medium">
                    {r.filename_original || r.filename}
                  </span>
                  {(r.is_primary || r.attachment_id === primaryResumeId) && (
                    <Badge className="shrink-0 text-xs bg-yellow-500/15 text-yellow-700 dark:text-yellow-300">
                      Primary
                    </Badge>
                  )}
                </div>
                <p className="text-xs text-muted-foreground">
                  {formatFileSize(r.size_bytes)} · {humanize(r.content_type.split("/")[1])} ·{" "}
                  {fmtTs(r.created_at)}
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-1">
                {r.url && (
                  <Button size="icon" variant="ghost" className="h-7 w-7" asChild>
                    <a href={r.url} target="_blank" rel="noreferrer" title="Download">
                      <Download className="h-3.5 w-3.5" />
                    </a>
                  </Button>
                )}
                {!r.is_primary && r.attachment_id !== primaryResumeId && (
                  <Button
                    size="icon"
                    variant="ghost"
                    className="h-7 w-7"
                    title="Set as primary"
                    onClick={() => setPrimaryMut.mutate(r.attachment_id)}
                    disabled={setPrimaryMut.isPending}
                  >
                    <Star className="h-3.5 w-3.5" />
                  </Button>
                )}
                <Button
                  size="icon"
                  variant="ghost"
                  className="h-7 w-7 text-destructive hover:text-destructive"
                  title="Delete"
                  onClick={() => deleteMut.mutate(r.attachment_id)}
                  disabled={deleteMut.isPending}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── History tab sub-component ────────────────────────────────────────────────

function HistorySection({ candidateId }: { candidateId: string }) {
  const historyQuery = useQuery({
    queryKey: ["ats-candidate-history", candidateId],
    queryFn: () => getCandidateHistory(candidateId, { limit: 50 }),
    retry: false,
  });

  if (historyQuery.isPending) {
    return (
      <div className="space-y-2">
        {[1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </div>
    );
  }

  const events = historyQuery.data?.events ?? [];

  if (events.length === 0) {
    return (
      <div className="rounded-lg border border-dashed p-8 text-center">
        <History className="mx-auto h-8 w-8 text-muted-foreground" />
        <p className="mt-2 text-sm text-muted-foreground">No activity recorded yet.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {events.map((ev) => (
        <div
          key={ev.event_id}
          className="flex gap-3 rounded-lg border p-3 text-sm"
        >
          <History className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
          <div className="flex-1 min-w-0">
            <div className="flex items-start justify-between gap-2">
              <span className="font-medium">{ev.summary || humanize(ev.change_type)}</span>
              <span className="shrink-0 text-xs text-muted-foreground">
                {fmtTs(ev.created_at)}
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              By {ev.actor_sub}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function CandidateDetailPage() {
  const { candidateId = "" } = useParams<{ candidateId: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [editing, setEditing] = useState(false);
  const [deleteDialog, setDeleteDialog] = useState(false);
  const [editForm, setEditForm] = useState<CandidateUpdateIn>({});

  const candidateQuery = useQuery({
    queryKey: ["ats-candidate", candidateId],
    queryFn: () => getCandidate(candidateId),
    retry: false,
    enabled: !!candidateId,
  });

  const updateMut = useMutation({
    mutationFn: (body: CandidateUpdateIn) => updateCandidate(candidateId, body),
    onSuccess: () => {
      toast.success("Candidate updated");
      setEditing(false);
      void qc.invalidateQueries({ queryKey: ["ats-candidate", candidateId] });
      void qc.invalidateQueries({ queryKey: ["ats-candidates"] });
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Update failed"),
  });

  const deleteMut = useMutation({
    mutationFn: () => deleteCandidate(candidateId),
    onSuccess: () => {
      toast.success("Candidate removed");
      navigate("/ats/candidates");
    },
    onError: (err) =>
      toast.error(err instanceof ApiError ? err.detail : "Delete failed"),
  });

  if (candidateQuery.isError) {
    if (isNotEnabled(candidateQuery.error)) {
      return <CandidatesNotEnabled />;
    }
    const status = (candidateQuery.error as ApiError)?.status;
    return (
      <div className="space-y-6">
        <PageHeader title="Candidate" />
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            {status === 410
              ? "This candidate has been removed."
              : "Candidate not found."}
          </CardContent>
        </Card>
      </div>
    );
  }

  if (candidateQuery.isPending) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-10 w-64" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  const c: Candidate = candidateQuery.data!;

  const startEdit = () => {
    setEditForm({
      first_name: c.first_name,
      last_name: c.last_name,
      email: c.email_raw || c.email,
      phone: c.phone ?? "",
      company: c.company ?? "",
      title: c.title ?? "",
      source: c.source,
      status: c.status,
      current_pay: c.current_pay ?? "",
      desired_pay: c.desired_pay ?? "",
      key_skills: c.key_skills ?? "",
      date_available: c.date_available ?? "",
      can_relocate: c.can_relocate,
      linkedin_url: c.linkedin_url ?? "",
      web_url: c.web_url ?? "",
      address: c.address ?? "",
      city: c.city ?? "",
      state: c.state ?? "",
      postal_code: c.postal_code ?? "",
      country: c.country ?? "",
    });
    setEditing(true);
  };

  const setF = <K extends keyof CandidateUpdateIn>(k: K, v: CandidateUpdateIn[K]) =>
    setEditForm((f) => ({ ...f, [k]: v }));

  const saveEdit = () => {
    const body: CandidateUpdateIn = {};
    // Only send changed fields (undefined = unchanged; empty string = clear)
    const keys: (keyof CandidateUpdateIn)[] = [
      "first_name", "last_name", "email", "phone", "company", "title",
      "source", "status", "current_pay", "desired_pay", "key_skills",
      "date_available", "can_relocate", "linkedin_url", "web_url",
      "address", "city", "state", "postal_code", "country",
    ];
    for (const k of keys) {
      if (editForm[k] !== undefined) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (body as any)[k] = editForm[k] === "" ? undefined : editForm[k];
      }
    }
    body.can_relocate = editForm.can_relocate;
    updateMut.mutate(body);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title={fullName(c.first_name, c.last_name)}
        description={[c.title, c.company].filter(Boolean).join(" at ") || "Candidate"}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={() => navigate("/ats/candidates")}>
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Button>
            {!editing && (
              <>
                <Button variant="outline" onClick={startEdit}>
                  <Edit2 className="mr-2 h-4 w-4" />
                  Edit
                </Button>
                <Button
                  variant="destructive"
                  size="icon"
                  onClick={() => setDeleteDialog(true)}
                  title="Delete candidate"
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </>
            )}
            {editing && (
              <>
                <Button onClick={saveEdit} disabled={updateMut.isPending}>
                  <Save className="mr-2 h-4 w-4" />
                  {updateMut.isPending ? "Saving…" : "Save"}
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => setEditing(false)}
                  disabled={updateMut.isPending}
                >
                  <X className="mr-2 h-4 w-4" />
                  Cancel
                </Button>
              </>
            )}
          </div>
        }
      />

      <Tabs defaultValue="profile">
        <TabsList>
          <TabsTrigger value="profile">
            <User className="mr-1.5 h-4 w-4" />
            Profile
          </TabsTrigger>
          <TabsTrigger value="resumes">
            <FileText className="mr-1.5 h-4 w-4" />
            Resumes
          </TabsTrigger>
          <TabsTrigger value="history">
            <History className="mr-1.5 h-4 w-4" />
            Activity
          </TabsTrigger>
        </TabsList>

        {/* ── Profile tab ── */}
        <TabsContent value="profile" className="space-y-4 pt-4">
          {/* Status + meta strip */}
          <Card>
            <CardContent className="pt-4">
              <div className="flex flex-wrap items-center gap-4">
                <Badge className={`text-sm ${statusColor(c.status)}`}>
                  {humanize(c.status)}
                </Badge>
                <span className="text-sm text-muted-foreground">
                  Source: {humanize(c.source)}
                </span>
                {c.can_relocate && (
                  <span className="text-sm text-muted-foreground">Open to relocation</span>
                )}
                {c.date_available && (
                  <span className="text-sm text-muted-foreground">
                    Available: {c.date_available}
                  </span>
                )}
              </div>
            </CardContent>
          </Card>

          {!editing ? (
            /* ── View mode ── */
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Contact</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3 text-sm">
                  <ProfileRow icon={<Mail className="h-4 w-4" />} label="Email">
                    <a href={`mailto:${c.email}`} className="hover:underline text-primary">
                      {c.email_raw || c.email}
                    </a>
                  </ProfileRow>
                  {c.phone && (
                    <ProfileRow icon={<Phone className="h-4 w-4" />} label="Phone">
                      {c.phone}
                    </ProfileRow>
                  )}
                  {c.linkedin_url && (
                    <ProfileRow icon={<Linkedin className="h-4 w-4" />} label="LinkedIn">
                      <a
                        href={c.linkedin_url}
                        target="_blank"
                        rel="noreferrer"
                        className="hover:underline text-primary truncate"
                      >
                        {c.linkedin_url}
                      </a>
                    </ProfileRow>
                  )}
                  {c.web_url && (
                    <ProfileRow icon={<Globe className="h-4 w-4" />} label="Website">
                      <a
                        href={c.web_url}
                        target="_blank"
                        rel="noreferrer"
                        className="hover:underline text-primary truncate"
                      >
                        {c.web_url}
                      </a>
                    </ProfileRow>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Employment</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3 text-sm">
                  {c.company && (
                    <ProfileRow icon={<Building2 className="h-4 w-4" />} label="Company">
                      {c.company}
                    </ProfileRow>
                  )}
                  {c.title && (
                    <ProfileRow icon={<Briefcase className="h-4 w-4" />} label="Title">
                      {c.title}
                    </ProfileRow>
                  )}
                  {c.current_pay && (
                    <ProfileRow icon={null} label="Current pay">
                      {c.current_pay}
                    </ProfileRow>
                  )}
                  {c.desired_pay && (
                    <ProfileRow icon={null} label="Desired pay">
                      {c.desired_pay}
                    </ProfileRow>
                  )}
                </CardContent>
              </Card>

              {(c.address || c.city || c.state || c.country) && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Location</CardTitle>
                  </CardHeader>
                  <CardContent className="text-sm">
                    <ProfileRow icon={<MapPin className="h-4 w-4" />} label="Address">
                      <span className="whitespace-pre-wrap">
                        {[c.address, [c.city, c.state, c.postal_code].filter(Boolean).join(", "), c.country]
                          .filter(Boolean)
                          .join("\n")}
                      </span>
                    </ProfileRow>
                  </CardContent>
                </Card>
              )}

              {c.key_skills && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Key Skills</CardTitle>
                  </CardHeader>
                  <CardContent className="text-sm whitespace-pre-wrap text-muted-foreground">
                    {c.key_skills}
                  </CardContent>
                </Card>
              )}

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Record info</CardTitle>
                </CardHeader>
                <CardContent className="space-y-1 text-sm text-muted-foreground">
                  <p>ID: {c.candidate_id}</p>
                  <p>Created: {fmtTs(c.created_at)}</p>
                  <p>Updated: {fmtTs(c.updated_at)}</p>
                  <p>Owner: {c.owner_sub}</p>
                  <p>Created by: {c.created_by}</p>
                </CardContent>
              </Card>
            </div>
          ) : (
            /* ── Edit mode ── */
            <div className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Basic information</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label>First name</Label>
                      <Input
                        value={editForm.first_name ?? ""}
                        onChange={(e) => setF("first_name", e.target.value)}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label>Last name</Label>
                      <Input
                        value={editForm.last_name ?? ""}
                        onChange={(e) => setF("last_name", e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label>Email</Label>
                      <Input
                        type="email"
                        value={editForm.email ?? ""}
                        onChange={(e) => setF("email", e.target.value)}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label>Phone</Label>
                      <Input
                        type="tel"
                        value={editForm.phone ?? ""}
                        onChange={(e) => setF("phone", e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label>Company</Label>
                      <Input
                        value={editForm.company ?? ""}
                        onChange={(e) => setF("company", e.target.value)}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label>Title</Label>
                      <Input
                        value={editForm.title ?? ""}
                        onChange={(e) => setF("title", e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label>Status</Label>
                      <Select
                        value={editForm.status ?? c.status}
                        onValueChange={(v) => setF("status", v)}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {CANDIDATE_STATUSES.map((s) => (
                            <SelectItem key={s} value={s}>
                              {humanize(s)}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-1.5">
                      <Label>Source</Label>
                      <Select
                        value={editForm.source ?? c.source}
                        onValueChange={(v) => setF("source", v)}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {CANDIDATE_SOURCES.map((s) => (
                            <SelectItem key={s} value={s}>
                              {humanize(s)}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">ATS details</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label>Current pay</Label>
                      <Input
                        value={editForm.current_pay ?? ""}
                        onChange={(e) => setF("current_pay", e.target.value)}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label>Desired pay</Label>
                      <Input
                        value={editForm.desired_pay ?? ""}
                        onChange={(e) => setF("desired_pay", e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label>Available from (YYYY-MM-DD)</Label>
                      <Input
                        value={editForm.date_available ?? ""}
                        onChange={(e) => setF("date_available", e.target.value)}
                        maxLength={10}
                      />
                    </div>
                    <div className="flex items-end pb-1">
                      <div className="flex items-center gap-2">
                        <Checkbox
                          id="edit_can_relocate"
                          checked={editForm.can_relocate ?? false}
                          onCheckedChange={(v) => setF("can_relocate", !!v)}
                        />
                        <Label htmlFor="edit_can_relocate">Open to relocation</Label>
                      </div>
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <Label>Key skills</Label>
                    <Textarea
                      rows={3}
                      value={editForm.key_skills ?? ""}
                      onChange={(e) => setF("key_skills", e.target.value)}
                      maxLength={4000}
                    />
                  </div>
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label>LinkedIn URL</Label>
                      <Input
                        value={editForm.linkedin_url ?? ""}
                        onChange={(e) => setF("linkedin_url", e.target.value)}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label>Website / Portfolio</Label>
                      <Input
                        value={editForm.web_url ?? ""}
                        onChange={(e) => setF("web_url", e.target.value)}
                      />
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Address</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-1.5">
                    <Label>Street address</Label>
                    <Input
                      value={editForm.address ?? ""}
                      onChange={(e) => setF("address", e.target.value)}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                    <div className="col-span-2 space-y-1.5">
                      <Label>City</Label>
                      <Input
                        value={editForm.city ?? ""}
                        onChange={(e) => setF("city", e.target.value)}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label>State</Label>
                      <Input
                        value={editForm.state ?? ""}
                        onChange={(e) => setF("state", e.target.value)}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label>Postal code</Label>
                      <Input
                        value={editForm.postal_code ?? ""}
                        onChange={(e) => setF("postal_code", e.target.value)}
                      />
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <Label>Country</Label>
                    <Input
                      value={editForm.country ?? ""}
                      onChange={(e) => setF("country", e.target.value)}
                    />
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        {/* ── Resumes tab ── */}
        <TabsContent value="resumes" className="pt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Resumes &amp; attachments</CardTitle>
            </CardHeader>
            <CardContent>
              <ResumeSection
                candidateId={c.candidate_id}
                primaryResumeId={c.primary_resume_id}
              />
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── History tab ── */}
        <TabsContent value="history" className="pt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Change history</CardTitle>
            </CardHeader>
            <CardContent>
              <HistorySection candidateId={c.candidate_id} />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Delete confirmation */}
      <AlertDialog open={deleteDialog} onOpenChange={setDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove candidate?</AlertDialogTitle>
            <AlertDialogDescription>
              This will soft-delete{" "}
              <strong>{fullName(c.first_name, c.last_name)}</strong> and set their
              status to archived. The record can be recovered by an administrator.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Keep</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => deleteMut.mutate()}
              disabled={deleteMut.isPending}
            >
              {deleteMut.isPending ? "Removing…" : "Remove"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

// ─── Tiny helper for profile rows ─────────────────────────────────────────────

function ProfileRow({
  icon,
  label,
  children,
}: {
  icon: React.ReactNode | null;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-3">
      {icon && <span className="mt-0.5 shrink-0 text-muted-foreground">{icon}</span>}
      {!icon && <span className="mt-0.5 shrink-0 w-4" />}
      <div>
        <p className="text-xs text-muted-foreground">{label}</p>
        <div className="mt-0.5">{children}</div>
      </div>
    </div>
  );
}
