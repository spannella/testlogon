import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ApiError } from "@/api/client";
import {
  createCandidate,
  CANDIDATE_STATUSES,
  CANDIDATE_SOURCES,
  type CandidateCreateIn,
} from "@/api/endpoints/candidates";
import { CandidatesNotEnabled } from "./CandidatesNotEnabled";
import { humanize, isNotEnabled } from "./candidateUtils";

const DEFAULT_FORM: CandidateCreateIn = {
  first_name: "",
  last_name: "",
  email: "",
  phone: "",
  company: "",
  title: "",
  source: "other",
  status: "active",
  current_pay: "",
  desired_pay: "",
  key_skills: "",
  date_available: "",
  can_relocate: false,
  linkedin_url: "",
  web_url: "",
  address: "",
  city: "",
  state: "",
  postal_code: "",
  country: "",
};

export default function CreateCandidatePage() {
  const navigate = useNavigate();
  const [form, setForm] = useState<CandidateCreateIn>(DEFAULT_FORM);
  const [notEnabled, setNotEnabled] = useState(false);

  const mut = useMutation({
    mutationFn: () => {
      // Build payload — omit empty optional strings
      const payload: CandidateCreateIn = {
        first_name: form.first_name.trim(),
        last_name: form.last_name.trim(),
        email: form.email.trim(),
        source: form.source || "other",
        status: form.status || "active",
        can_relocate: form.can_relocate ?? false,
      };
      if (form.phone?.trim()) payload.phone = form.phone.trim();
      if (form.company?.trim()) payload.company = form.company.trim();
      if (form.title?.trim()) payload.title = form.title.trim();
      if (form.current_pay?.trim()) payload.current_pay = form.current_pay.trim();
      if (form.desired_pay?.trim()) payload.desired_pay = form.desired_pay.trim();
      if (form.key_skills?.trim()) payload.key_skills = form.key_skills.trim();
      if (form.date_available?.trim()) payload.date_available = form.date_available.trim();
      if (form.linkedin_url?.trim()) payload.linkedin_url = form.linkedin_url.trim();
      if (form.web_url?.trim()) payload.web_url = form.web_url.trim();
      if (form.address?.trim()) payload.address = form.address.trim();
      if (form.city?.trim()) payload.city = form.city.trim();
      if (form.state?.trim()) payload.state = form.state.trim();
      if (form.postal_code?.trim()) payload.postal_code = form.postal_code.trim();
      if (form.country?.trim()) payload.country = form.country.trim();
      return createCandidate(payload);
    },
    onSuccess: (candidate) => {
      toast.success("Candidate created");
      navigate(`/ats/candidates/${candidate.candidate_id}`);
    },
    onError: (err) => {
      if (err instanceof ApiError && isNotEnabled(err)) {
        setNotEnabled(true);
        return;
      }
      toast.error(err instanceof ApiError ? err.detail : "Failed to create candidate");
    },
  });

  const setField = <K extends keyof CandidateCreateIn>(k: K, v: CandidateCreateIn[K]) =>
    setForm((f) => ({ ...f, [k]: v }));

  const canSubmit =
    form.first_name.trim().length > 0 &&
    form.last_name.trim().length > 0 &&
    form.email.trim().length >= 3;

  if (notEnabled) {
    return (
      <div className="space-y-6">
        <PageHeader title="New Candidate" description="Add a candidate to your ATS pipeline" />
        <CandidatesNotEnabled />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="New Candidate"
        description="Add a candidate to your ATS pipeline"
        actions={
          <Button variant="outline" onClick={() => navigate("/ats/candidates")}>
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Candidates
          </Button>
        }
      />

      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (canSubmit) mut.mutate();
        }}
        className="space-y-6"
      >
        {/* Basic info */}
        <Card>
          <CardHeader>
            <CardTitle>Basic information</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="first_name">First name *</Label>
                <Input
                  id="first_name"
                  value={form.first_name}
                  onChange={(e) => setField("first_name", e.target.value)}
                  required
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="last_name">Last name *</Label>
                <Input
                  id="last_name"
                  value={form.last_name}
                  onChange={(e) => setField("last_name", e.target.value)}
                  required
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="email">Email *</Label>
              <Input
                id="email"
                type="email"
                value={form.email}
                onChange={(e) => setField("email", e.target.value)}
                required
              />
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="phone">Phone</Label>
                <Input
                  id="phone"
                  type="tel"
                  value={form.phone ?? ""}
                  onChange={(e) => setField("phone", e.target.value)}
                  placeholder="+1 555-000-0000"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="company">Current company</Label>
                <Input
                  id="company"
                  value={form.company ?? ""}
                  onChange={(e) => setField("company", e.target.value)}
                />
              </div>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="title">Current title</Label>
                <Input
                  id="title"
                  value={form.title ?? ""}
                  onChange={(e) => setField("title", e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="source">Source</Label>
                <Select value={form.source ?? "other"} onValueChange={(v) => setField("source", v)}>
                  <SelectTrigger id="source">
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

            <div className="space-y-1.5">
              <Label htmlFor="status">Initial status</Label>
              <Select value={form.status ?? "active"} onValueChange={(v) => setField("status", v)}>
                <SelectTrigger id="status" className="max-w-[200px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CANDIDATE_STATUSES.filter((s) => s !== "archived").map((s) => (
                    <SelectItem key={s} value={s}>
                      {humanize(s)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </CardContent>
        </Card>

        {/* ATS fields */}
        <Card>
          <CardHeader>
            <CardTitle>ATS details</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="current_pay">Current pay</Label>
                <Input
                  id="current_pay"
                  value={form.current_pay ?? ""}
                  onChange={(e) => setField("current_pay", e.target.value)}
                  placeholder="e.g. $95k / year"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="desired_pay">Desired pay</Label>
                <Input
                  id="desired_pay"
                  value={form.desired_pay ?? ""}
                  onChange={(e) => setField("desired_pay", e.target.value)}
                  placeholder="e.g. $110k / year"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="date_available">Available from (YYYY-MM-DD)</Label>
                <Input
                  id="date_available"
                  value={form.date_available ?? ""}
                  onChange={(e) => setField("date_available", e.target.value)}
                  placeholder="2026-07-01"
                  maxLength={10}
                />
              </div>
              <div className="flex items-end pb-1">
                <div className="flex items-center gap-2">
                  <Checkbox
                    id="can_relocate"
                    checked={form.can_relocate ?? false}
                    onCheckedChange={(v) => setField("can_relocate", !!v)}
                  />
                  <Label htmlFor="can_relocate">Open to relocation</Label>
                </div>
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="key_skills">Key skills</Label>
              <Textarea
                id="key_skills"
                rows={3}
                value={form.key_skills ?? ""}
                onChange={(e) => setField("key_skills", e.target.value)}
                placeholder="Comma-separated skills, technologies, or a prose description…"
                maxLength={4000}
              />
              <p className="text-xs text-muted-foreground text-right">
                {(form.key_skills ?? "").length}/4000
              </p>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="linkedin_url">LinkedIn URL</Label>
                <Input
                  id="linkedin_url"
                  value={form.linkedin_url ?? ""}
                  onChange={(e) => setField("linkedin_url", e.target.value)}
                  placeholder="https://linkedin.com/in/…"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="web_url">Website / Portfolio</Label>
                <Input
                  id="web_url"
                  value={form.web_url ?? ""}
                  onChange={(e) => setField("web_url", e.target.value)}
                  placeholder="https://…"
                />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Address */}
        <Card>
          <CardHeader>
            <CardTitle>Address</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="address">Street address</Label>
              <Input
                id="address"
                value={form.address ?? ""}
                onChange={(e) => setField("address", e.target.value)}
              />
            </div>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <div className="col-span-2 sm:col-span-2 space-y-1.5">
                <Label htmlFor="city">City</Label>
                <Input
                  id="city"
                  value={form.city ?? ""}
                  onChange={(e) => setField("city", e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="state">State / Region</Label>
                <Input
                  id="state"
                  value={form.state ?? ""}
                  onChange={(e) => setField("state", e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="postal_code">Postal code</Label>
                <Input
                  id="postal_code"
                  value={form.postal_code ?? ""}
                  onChange={(e) => setField("postal_code", e.target.value)}
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="country">Country</Label>
              <Input
                id="country"
                value={form.country ?? ""}
                onChange={(e) => setField("country", e.target.value)}
                placeholder="United States"
              />
            </div>
          </CardContent>
        </Card>

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={() => navigate("/ats/candidates")}>
            Cancel
          </Button>
          <Button type="submit" disabled={!canSubmit || mut.isPending}>
            {mut.isPending ? "Creating…" : "Create Candidate"}
          </Button>
        </div>
      </form>
    </div>
  );
}
