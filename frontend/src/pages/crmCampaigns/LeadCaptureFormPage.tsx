import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { CheckCircle2, MapPin } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { ApiError } from "@/api/client";
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

import { captureWebLead } from "@/api/endpoints/crmCampaigns";
import { CampaignsNotEnabled } from "./CampaignsNotEnabled";

export default function LeadCaptureFormPage() {
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [company, setCompany] = useState("");
  const [message, setMessage] = useState("");
  const [campaignId, setCampaignId] = useState("");
  // Honeypot bot-trap; should remain empty for real submissions (CMP-006).
  const [honeypot, setHoneypot] = useState("");
  const [disabled, setDisabled] = useState(false);

  const captureMut = useMutation({
    mutationFn: () =>
      captureWebLead({
        first_name: firstName.trim(),
        last_name: lastName.trim(),
        email: email.trim(),
        phone: phone.trim() || undefined,
        company: company.trim() || undefined,
        message: message.trim() || undefined,
        campaign_id: campaignId.trim() || undefined,
        honeypot: honeypot || undefined,
      }),
    onSuccess: () => {
      toast.success("Lead submitted");
      setFirstName("");
      setLastName("");
      setEmail("");
      setPhone("");
      setCompany("");
      setMessage("");
    },
    onError: (e) => {
      if (e instanceof ApiError && (e.status === 404 || e.status === 503)) {
        setDisabled(true);
        return;
      }
      toast.error(e instanceof ApiError ? e.detail : "Submission failed");
    },
  });

  if (disabled) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Lead Capture Form"
          description="Web-to-lead capture form."
        />
        <CampaignsNotEnabled feature="Web-to-lead capture" status={404} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Lead Capture Form"
        description="Submit and test web-to-lead form captures."
      />

      <Card className="max-w-xl">
        <CardHeader>
          <CardTitle className="text-base">Contact us</CardTitle>
          <CardDescription>
            Capture a new marketing lead. Submissions are stored and (optionally)
            attributed to a campaign.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {captureMut.isSuccess ? (
            <div className="flex flex-col items-center gap-2 py-6 text-center">
              <CheckCircle2 className="h-8 w-8 text-green-600" />
              <p className="text-sm">Thanks! Your lead has been recorded.</p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => captureMut.reset()}
              >
                Submit another
              </Button>
            </div>
          ) : (
            <form
              className="space-y-4"
              onSubmit={(e) => {
                e.preventDefault();
                captureMut.mutate();
              }}
            >
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label htmlFor="lc-first">First name</Label>
                  <Input
                    id="lc-first"
                    value={firstName}
                    onChange={(e) => setFirstName(e.target.value)}
                    required
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="lc-last">Last name</Label>
                  <Input
                    id="lc-last"
                    value={lastName}
                    onChange={(e) => setLastName(e.target.value)}
                    required
                  />
                </div>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="lc-email">Email</Label>
                <Input
                  id="lc-email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label htmlFor="lc-phone">Phone</Label>
                  <Input
                    id="lc-phone"
                    value={phone}
                    onChange={(e) => setPhone(e.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="lc-company">Company</Label>
                  <Input
                    id="lc-company"
                    value={company}
                    onChange={(e) => setCompany(e.target.value)}
                  />
                </div>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="lc-message">Message</Label>
                <Textarea
                  id="lc-message"
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  rows={3}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="lc-campaign">Campaign ID (optional)</Label>
                <Input
                  id="lc-campaign"
                  value={campaignId}
                  onChange={(e) => setCampaignId(e.target.value)}
                  placeholder="Attribute to a campaign"
                />
              </div>
              {/* Honeypot — visually hidden bot trap (CMP-006) */}
              <input
                type="text"
                tabIndex={-1}
                autoComplete="off"
                aria-hidden="true"
                value={honeypot}
                onChange={(e) => setHoneypot(e.target.value)}
                style={{ position: "absolute", left: "-9999px" }}
              />
              <Button
                type="submit"
                className="w-full"
                disabled={
                  captureMut.isPending ||
                  !firstName.trim() ||
                  !lastName.trim() ||
                  !email.trim()
                }
              >
                <MapPin className="mr-1 h-4 w-4" /> Submit lead
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
