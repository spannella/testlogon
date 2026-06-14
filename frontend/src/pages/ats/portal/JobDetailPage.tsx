/**
 * Public career portal — job detail + application form.
 * Route: /ats/portal/jobs/:slug  (public, no auth required)
 *
 * Renders the full job description and inline application form including
 * optional resume upload (PRT-005). After a successful submit it navigates
 * to the confirmation page.
 *
 * Feature flag: 404 from backend → "not available" state.
 */

import { useState, useRef } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { useQuery, useMutation } from "@tanstack/react-query";
import {
  Briefcase,
  MapPin,
  Clock,
  Users,
  ArrowLeft,
  Loader2,
  AlertCircle,
  Paperclip,
  X,
} from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";

import {
  getPublicJob,
  presignResumeUpload,
  applyToJob,
  isCareerPortalNotEnabled,
  type CareerApplyIn,
} from "@/api/endpoints/careerPortal";
import { ApiError } from "@/api/client";

// ─── Helpers ─────────────────────────────────────────────────────

function formatEmploymentType(t: string | null): string {
  if (!t) return "";
  return (
    {
      full_time: "Full-time",
      part_time: "Part-time",
      contract: "Contract",
      temp: "Temporary",
      referral: "Referral",
    }[t] ?? t
  );
}

function formatPostedAt(ts: number): string {
  if (!ts) return "";
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    year: "numeric",
    month: "long",
    day: "numeric",
  });
}

const RESUME_ALLOWED_TYPES: Record<string, string> = {
  "application/pdf": ".pdf",
  "application/msword": ".doc",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
    ".docx",
};
const RESUME_MAX_BYTES = 10 * 1024 * 1024; // 10 MB

// ─── Resume upload helper ─────────────────────────────────────────

async function uploadResume(
  slug: string,
  file: File,
): Promise<string> {
  // 1. Get presigned URL
  const presign = await presignResumeUpload(slug, {
    filename: file.name,
    content_type: file.type,
    size_bytes: file.size,
  });

  // 2. PUT the file directly to S3 (or mock in dev)
  const putRes = await fetch(presign.upload_url, {
    method: "PUT",
    headers: { "Content-Type": file.type },
    body: file,
  });
  if (!putRes.ok) {
    throw new Error(`Resume upload failed (HTTP ${putRes.status})`);
  }

  return presign.ticket_id;
}

// ─── Page ─────────────────────────────────────────────────────────

export default function JobDetailPage() {
  const { slug } = useParams<{ slug: string }>();
  const navigate = useNavigate();

  // Form state
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [coverNote, setCoverNote] = useState("");
  const [resumeFile, setResumeFile] = useState<File | null>(null);
  const [resumeError, setResumeError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const jobQuery = useQuery({
    queryKey: ["career-portal", "job", slug],
    queryFn: () => getPublicJob(slug!),
    enabled: !!slug,
    retry: (count, err) => !isCareerPortalNotEnabled(err) && count < 2,
  });

  const applyMut = useMutation({
    mutationFn: async () => {
      let resumeTicketId: string | undefined;

      if (resumeFile) {
        resumeTicketId = await uploadResume(slug!, resumeFile);
      }

      const body: CareerApplyIn = {
        first_name: firstName.trim(),
        last_name: lastName.trim(),
        email: email.trim(),
        phone: phone.trim() || undefined,
        cover_note: coverNote.trim() || undefined,
        resume_ticket_id: resumeTicketId,
      };

      return applyToJob(slug!, body);
    },
    onSuccess: (res) => {
      navigate(`/ats/portal/confirmation/${res.application_id}`, {
        state: {
          jobTitle: jobQuery.data?.title ?? "this position",
          applicationId: res.application_id,
          firstName: firstName.trim(),
        },
      });
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError && err.status === 429) {
        toast.error("Too many applications. Please try again later.");
      } else {
        toast.error(
          err instanceof Error ? err.message : "Failed to submit application.",
        );
      }
    },
  });

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setResumeError(null);
    const file = e.target.files?.[0] ?? null;
    if (!file) {
      setResumeFile(null);
      return;
    }
    if (!(file.type in RESUME_ALLOWED_TYPES)) {
      setResumeError("Only PDF, DOC, and DOCX files are accepted.");
      setResumeFile(null);
      return;
    }
    if (file.size > RESUME_MAX_BYTES) {
      setResumeError("Resume must be 10 MB or smaller.");
      setResumeFile(null);
      return;
    }
    setResumeFile(file);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!firstName.trim() || !lastName.trim() || !email.trim()) {
      toast.error("Please fill in all required fields.");
      return;
    }
    applyMut.mutate();
  };

  const isDisabled = isCareerPortalNotEnabled(jobQuery.error);

  if (isDisabled) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center gap-4 px-4">
        <Briefcase className="h-12 w-12 text-muted-foreground/40" />
        <div>
          <h2 className="text-xl font-semibold">Job Not Available</h2>
          <p className="text-sm text-muted-foreground mt-1">
            This job posting could not be found or is no longer available.
          </p>
        </div>
        <Button asChild variant="outline" size="sm">
          <Link to="/ats/portal/jobs">
            <ArrowLeft className="h-4 w-4 mr-1" /> Back to Jobs
          </Link>
        </Button>
      </div>
    );
  }

  if (jobQuery.isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (jobQuery.isError) {
    const status = jobQuery.error instanceof ApiError ? jobQuery.error.status : 0;
    return (
      <div className="flex flex-col items-center justify-center py-24 gap-3 text-center px-4">
        <AlertCircle className="h-8 w-8 text-destructive" />
        <p className="text-sm text-muted-foreground">
          {status === 404
            ? "This job posting could not be found."
            : "Failed to load job details."}
        </p>
        <Button asChild variant="outline" size="sm">
          <Link to="/ats/portal/jobs">
            <ArrowLeft className="h-4 w-4 mr-1" /> Back to Jobs
          </Link>
        </Button>
      </div>
    );
  }

  const job = jobQuery.data!;
  const empType = formatEmploymentType(job.employment_type);

  return (
    <div className="max-w-3xl mx-auto px-4 py-10 space-y-8">
      {/* Back navigation */}
      <Button asChild variant="ghost" size="sm" className="-ml-2">
        <Link to="/ats/portal/jobs">
          <ArrowLeft className="h-4 w-4 mr-1" /> All Open Positions
        </Link>
      </Button>

      {/* Job header */}
      <div className="space-y-3">
        <h1 className="text-3xl font-bold tracking-tight">{job.title}</h1>
        <div className="flex flex-wrap gap-3 text-sm text-muted-foreground">
          {job.location && (
            <span className="inline-flex items-center gap-1">
              <MapPin className="h-4 w-4" /> {job.location}
            </span>
          )}
          {empType && (
            <Badge variant="secondary">{empType}</Badge>
          )}
          {job.openings > 1 && (
            <span className="inline-flex items-center gap-1">
              <Users className="h-4 w-4" /> {job.openings} openings
            </span>
          )}
          {job.posted_at > 0 && (
            <span className="inline-flex items-center gap-1">
              <Clock className="h-4 w-4" /> Posted {formatPostedAt(job.posted_at)}
            </span>
          )}
        </div>
      </div>

      {/* Job description */}
      {job.public_description && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">About this role</CardTitle>
          </CardHeader>
          <CardContent>
            <div
              className="prose prose-sm max-w-none text-foreground"
              dangerouslySetInnerHTML={{ __html: job.public_description }}
            />
          </CardContent>
        </Card>
      )}

      {/* Application form */}
      <Card>
        <CardHeader>
          <CardTitle>Apply for this position</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="firstName">
                  First name <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="firstName"
                  value={firstName}
                  onChange={(e) => setFirstName(e.target.value)}
                  placeholder="Jane"
                  maxLength={120}
                  required
                  disabled={applyMut.isPending}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="lastName">
                  Last name <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="lastName"
                  value={lastName}
                  onChange={(e) => setLastName(e.target.value)}
                  placeholder="Doe"
                  maxLength={120}
                  required
                  disabled={applyMut.isPending}
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="email">
                Email address <span className="text-destructive">*</span>
              </Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="jane@example.com"
                maxLength={254}
                required
                disabled={applyMut.isPending}
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="phone">Phone number</Label>
              <Input
                id="phone"
                type="tel"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                placeholder="+1 555 000 0000"
                maxLength={30}
                disabled={applyMut.isPending}
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="coverNote">Cover note</Label>
              <Textarea
                id="coverNote"
                value={coverNote}
                onChange={(e) => setCoverNote(e.target.value)}
                placeholder="Tell us why you're a great fit for this role…"
                rows={5}
                maxLength={4000}
                disabled={applyMut.isPending}
              />
              <p className="text-xs text-muted-foreground">
                {coverNote.length}/4000 characters
              </p>
            </div>

            {/* Resume upload */}
            <div className="space-y-2">
              <Label>Resume</Label>
              <div className="flex items-center gap-3">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={applyMut.isPending}
                  onClick={() => fileInputRef.current?.click()}
                >
                  <Paperclip className="h-4 w-4 mr-1.5" />
                  {resumeFile ? "Change resume" : "Attach resume"}
                </Button>
                {resumeFile && (
                  <div className="flex items-center gap-1.5 text-sm">
                    <span className="text-muted-foreground truncate max-w-[200px]">
                      {resumeFile.name}
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        setResumeFile(null);
                        if (fileInputRef.current) fileInputRef.current.value = "";
                      }}
                      className="text-muted-foreground hover:text-destructive"
                      aria-label="Remove resume"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                )}
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".pdf,.doc,.docx,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                  className="hidden"
                  onChange={handleFileChange}
                />
              </div>
              {resumeError && (
                <p className="text-xs text-destructive">{resumeError}</p>
              )}
              <p className="text-xs text-muted-foreground">
                PDF, DOC, or DOCX — max 10 MB
              </p>
            </div>

            {/* Bot trap — hidden from users, filled by bots */}
            <input
              type="text"
              name="website"
              tabIndex={-1}
              aria-hidden="true"
              style={{ display: "none" }}
              autoComplete="off"
            />

            <div className="flex items-center justify-between pt-2">
              <p className="text-xs text-muted-foreground">
                <span className="text-destructive">*</span> Required fields
              </p>
              <Button
                type="submit"
                disabled={applyMut.isPending}
                className="min-w-[120px]"
              >
                {applyMut.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Submitting…
                  </>
                ) : (
                  "Submit Application"
                )}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
