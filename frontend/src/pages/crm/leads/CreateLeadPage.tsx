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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ApiError } from "@/api/client";
import { createLead, LEAD_SOURCES, type LeadCreateIn } from "@/api/endpoints/leads";
import { LeadsNotEnabled } from "./LeadsNotEnabled";
import { humanize, isNotEnabled } from "./leadUtils";

const EMPTY: LeadCreateIn = {
  first_name: "",
  last_name: "",
  email: "",
  phone: "",
  company: "",
  title: "",
  lead_source: "other",
  website: "",
  description: "",
};

export default function CreateLeadPage() {
  const navigate = useNavigate();
  const [form, setForm] = useState<LeadCreateIn>(EMPTY);
  const [notEnabled, setNotEnabled] = useState(false);

  const mut = useMutation({
    mutationFn: () => {
      // Trim out empty optionals so we don't send empty strings.
      const payload: LeadCreateIn = {
        first_name: form.first_name.trim(),
        last_name: form.last_name.trim(),
        email: form.email.trim(),
        lead_source: form.lead_source,
      };
      if (form.phone?.trim()) payload.phone = form.phone.trim();
      if (form.company?.trim()) payload.company = form.company.trim();
      if (form.title?.trim()) payload.title = form.title.trim();
      if (form.website?.trim()) payload.website = form.website.trim();
      if (form.description?.trim()) payload.description = form.description.trim();
      return createLead(payload);
    },
    onSuccess: (lead) => {
      toast.success("Lead created");
      navigate(`/crm/leads/${lead.lead_id}`);
    },
    onError: (err) => {
      if (err instanceof ApiError && isNotEnabled(err)) {
        setNotEnabled(true);
        return;
      }
      toast.error(err instanceof ApiError ? err.detail : "Failed to create lead");
    },
  });

  const setField = (k: keyof LeadCreateIn, v: string) => setForm((f) => ({ ...f, [k]: v }));

  const canSubmit =
    form.first_name.trim() && form.last_name.trim() && form.email.trim().length >= 3;

  if (notEnabled) {
    return (
      <div className="space-y-6">
        <PageHeader title="New Lead" description="Capture a new SuiteCRM lead" />
        <LeadsNotEnabled />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="New Lead"
        description="Capture a new SuiteCRM lead"
        actions={
          <Button variant="outline" onClick={() => navigate("/crm/leads")}>
            <ArrowLeft className="mr-2 h-4 w-4" /> Back to Leads
          </Button>
        }
      />

      <Card className="max-w-2xl">
        <CardHeader>
          <CardTitle>Lead details</CardTitle>
        </CardHeader>
        <CardContent>
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (canSubmit) mut.mutate();
            }}
          >
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
                  value={form.phone ?? ""}
                  onChange={(e) => setField("phone", e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="lead_source">Source</Label>
                <Select
                  value={form.lead_source}
                  onValueChange={(v) => setField("lead_source", v)}
                >
                  <SelectTrigger id="lead_source">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {LEAD_SOURCES.map((s) => (
                      <SelectItem key={s} value={s}>
                        {humanize(s)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="company">Company</Label>
                <Input
                  id="company"
                  value={form.company ?? ""}
                  onChange={(e) => setField("company", e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="title">Title</Label>
                <Input
                  id="title"
                  value={form.title ?? ""}
                  onChange={(e) => setField("title", e.target.value)}
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="website">Website</Label>
              <Input
                id="website"
                value={form.website ?? ""}
                onChange={(e) => setField("website", e.target.value)}
                placeholder="https://example.com"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                rows={4}
                value={form.description ?? ""}
                onChange={(e) => setField("description", e.target.value)}
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" variant="outline" onClick={() => navigate("/crm/leads")}>
                Cancel
              </Button>
              <Button type="submit" disabled={!canSubmit || mut.isPending}>
                {mut.isPending ? "Creating…" : "Create Lead"}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
