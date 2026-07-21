import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { ShieldMinus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/PageHeader";
import { ApiError } from "@/api/client";
import { toast } from "sonner";
import {
  revokeEntitlement,
  extendEntitlement,
  creditAdjustEntitlement,
  type EntitlementReasonCode,
} from "@/api/endpoints/adminEntitlements";

const REASONS: EntitlementReasonCode[] = [
  "customer_support",
  "fraud_review",
  "billing_correction",
  "incident_remediation",
  "goodwill",
];

function ReasonPicker({ value, onChange }: { value: EntitlementReasonCode; onChange: (v: EntitlementReasonCode) => void }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value as EntitlementReasonCode)}
      className="h-9 w-full rounded-md border bg-background px-2 text-sm capitalize">
      {REASONS.map((r) => <option key={r} value={r}>{r.replace(/_/g, " ")}</option>)}
    </select>
  );
}

export default function EntitlementsAdminPage() {
  const [id, setId] = useState("");
  const [reason, setReason] = useState<EntitlementReasonCode>("customer_support");
  const [comment, setComment] = useState("");
  const [extendHours, setExtendHours] = useState("24");
  const [creditUnits, setCreditUnits] = useState("");

  const revokeMut = useMutation({
    mutationFn: () => revokeEntitlement(id.trim(), { reason_code: reason, audit_comment: comment.trim() }),
    onSuccess: () => toast.success("Entitlement revoked"),
    onError: (err: unknown) => toast.error(err instanceof ApiError ? err.detail : "Revoke failed"),
  });

  const extendMut = useMutation({
    mutationFn: () => extendEntitlement(id.trim(), { reason_code: reason, audit_comment: comment.trim(), extend_hours: parseInt(extendHours, 10) || 0 }),
    onSuccess: () => toast.success("Entitlement extended"),
    onError: (err: unknown) => toast.error(err instanceof ApiError ? err.detail : "Extend failed"),
  });

  const creditMut = useMutation({
    mutationFn: () => creditAdjustEntitlement(id.trim(), { reason_code: reason, audit_comment: comment.trim(), credit_units: parseInt(creditUnits, 10) || 0 }),
    onSuccess: () => toast.success("Credits adjusted"),
    onError: (err: unknown) => toast.error(err instanceof ApiError ? err.detail : "Credit adjust failed"),
  });

  const idAndComment = !id.trim() || comment.trim().length < 5;

  return (
    <div className="mx-auto w-full max-w-2xl space-y-6 p-4 sm:p-6">
      <PageHeader title="Entitlements Admin" description="Revoke, extend, or credit-adjust a customer entitlement (billing-support scoped)" />

      <Card>
        <CardContent className="space-y-3 p-4">
          <div className="space-y-1.5">
            <Label htmlFor="ent-id">Entitlement ID</Label>
            <Input id="ent-id" placeholder="entitlement id" value={id} onChange={(e) => setId(e.target.value)} className="font-mono" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>Reason code</Label>
              <ReasonPicker value={reason} onChange={setReason} />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ent-comment">Audit comment (min 5 chars)</Label>
            <Textarea id="ent-comment" rows={2} value={comment} onChange={(e) => setComment(e.target.value)} />
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="revoke">
        <TabsList>
          <TabsTrigger value="revoke"><ShieldMinus className="mr-1 h-3.5 w-3.5" /> Revoke</TabsTrigger>
          <TabsTrigger value="extend">Extend</TabsTrigger>
          <TabsTrigger value="credits">Credits</TabsTrigger>
        </TabsList>

        <TabsContent value="revoke" className="pt-4">
          <Card><CardContent className="space-y-3 p-4">
            <p className="text-sm text-muted-foreground">Immediately revoke the entitlement.</p>
            <Button variant="destructive" disabled={idAndComment || revokeMut.isPending} onClick={() => revokeMut.mutate()}>
              Revoke entitlement
            </Button>
          </CardContent></Card>
        </TabsContent>

        <TabsContent value="extend" className="pt-4">
          <Card><CardContent className="space-y-3 p-4">
            <div className="space-y-1.5">
              <Label htmlFor="ext-hours">Extend by (hours)</Label>
              <Input id="ext-hours" type="number" value={extendHours} onChange={(e) => setExtendHours(e.target.value)} className="w-40" />
            </div>
            <Button disabled={idAndComment || !extendHours.trim() || extendMut.isPending} onClick={() => extendMut.mutate()}>
              Extend entitlement
            </Button>
          </CardContent></Card>
        </TabsContent>

        <TabsContent value="credits" className="pt-4">
          <Card><CardContent className="space-y-3 p-4">
            <div className="space-y-1.5">
              <Label htmlFor="credit-units">Credit units to add</Label>
              <Input id="credit-units" type="number" value={creditUnits} onChange={(e) => setCreditUnits(e.target.value)} className="w-40" />
            </div>
            <Button disabled={idAndComment || !creditUnits.trim() || creditMut.isPending} onClick={() => creditMut.mutate()}>
              Adjust credits
            </Button>
          </CardContent></Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
