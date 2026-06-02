import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

import {
  getWorkloads,
  getSlaConfig,
  getSlaBreaches,
  getMyQueue,
  reassignCase,
  updateSlaConfig,
  escalateCase,
} from "@/api/endpoints/kycAssignment";
import type {
  KycAdminAvailability,
  KycSlaTierConfig,
} from "@/api/types";

const SLA_TIERS = ["tier_1", "tier_2", "tier_3"];

function ReassignDialog({
  caseId,
  admins,
  onClose,
}: {
  caseId: string;
  admins: KycAdminAvailability[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [adminSub, setAdminSub] = useState("");
  const [reason, setReason] = useState("");

  const mut = useMutation({
    mutationFn: () => reassignCase(caseId, { new_admin_sub: adminSub, reason }),
    onSuccess: () => {
      toast.success("Case reassigned");
      qc.invalidateQueries({ queryKey: ["kyc-workloads"] });
      qc.invalidateQueries({ queryKey: ["kyc-my-queue"] });
      onClose();
    },
    onError: () => toast.error("Reassignment failed"),
  });

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reassign case {caseId}</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label>New assignee</Label>
            <Select value={adminSub} onValueChange={setAdminSub}>
              <SelectTrigger data-testid="reassign-admin-select">
                <SelectValue placeholder="Select an admin" />
              </SelectTrigger>
              <SelectContent>
                {admins.map((a) => (
                  <SelectItem key={a.admin_sub} value={a.admin_sub}>
                    {a.admin_sub} ({a.current_case_count}/{a.max_cases})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Reason</Label>
            <Textarea
              data-testid="reassign-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Why are you reassigning this case?"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            data-testid="reassign-submit"
            disabled={!adminSub || reason.trim().length < 3 || mut.isPending}
            onClick={() => mut.mutate()}
          >
            Reassign
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function SlaConfigRow({ tier, config }: { tier: string; config: KycSlaTierConfig }) {
  const qc = useQueryClient();
  const [targetHours, setTargetHours] = useState(String(config.target_hours));
  const [warningPct, setWarningPct] = useState(String(config.warning_pct));

  const mut = useMutation({
    mutationFn: () =>
      updateSlaConfig(tier, {
        target_hours: Number(targetHours),
        warning_pct: Number(warningPct),
      }),
    onSuccess: () => {
      toast.success(`SLA for ${tier} updated`);
      qc.invalidateQueries({ queryKey: ["kyc-sla-config"] });
      qc.invalidateQueries({ queryKey: ["kyc-workloads"] });
    },
    onError: () => toast.error("Update failed (root session required)"),
  });

  return (
    <TableRow data-testid={`sla-row-${tier}`}>
      <TableCell>
        <Badge variant="secondary">{tier}</Badge>
      </TableCell>
      <TableCell>
        <Input
          className="w-24"
          data-testid={`sla-target-${tier}`}
          value={targetHours}
          onChange={(e) => setTargetHours(e.target.value)}
        />
      </TableCell>
      <TableCell>
        <Input
          className="w-24"
          data-testid={`sla-warning-${tier}`}
          value={warningPct}
          onChange={(e) => setWarningPct(e.target.value)}
        />
      </TableCell>
      <TableCell>
        <Button
          size="sm"
          data-testid={`sla-save-${tier}`}
          disabled={mut.isPending}
          onClick={() => mut.mutate()}
        >
          Save
        </Button>
      </TableCell>
    </TableRow>
  );
}

export default function KycWorkloadPage() {
  const qc = useQueryClient();
  const [reassignCaseId, setReassignCaseId] = useState<string | null>(null);

  const workloads = useQuery({
    queryKey: ["kyc-workloads"],
    queryFn: getWorkloads,
  });
  const slaConfig = useQuery({
    queryKey: ["kyc-sla-config"],
    queryFn: getSlaConfig,
  });
  const breaches = useQuery({
    queryKey: ["kyc-sla-breaches"],
    queryFn: getSlaBreaches,
  });
  const myQueue = useQuery({
    queryKey: ["kyc-my-queue"],
    queryFn: getMyQueue,
  });

  const escalateMut = useMutation({
    mutationFn: (caseId: string) => escalateCase(caseId),
    onSuccess: () => {
      toast.success("Case escalated");
      qc.invalidateQueries({ queryKey: ["kyc-sla-breaches"] });
      qc.invalidateQueries({ queryKey: ["kyc-workloads"] });
    },
    onError: () => toast.error("Escalation failed"),
  });

  const admins = workloads.data?.admins ?? [];
  const sla = useMemo(
    () => slaConfig.data?.sla_config ?? workloads.data?.sla_config ?? {},
    [slaConfig.data, workloads.data],
  );

  return (
    <div className="space-y-6 p-6" data-testid="kyc-workload-page">
      <div>
        <h1 className="text-2xl font-semibold">KYC Workload & Assignment</h1>
        <p className="text-sm text-muted-foreground">
          Case distribution, SLA enforcement, and manual reassignment.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Total Active Cases</CardTitle>
          </CardHeader>
          <CardContent className="text-3xl font-bold" data-testid="stat-active-cases">
            {workloads.data?.total_active_cases ?? 0}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">On-Duty Admins</CardTitle>
          </CardHeader>
          <CardContent className="text-3xl font-bold" data-testid="stat-on-duty">
            {workloads.data?.total_on_duty_admins ?? 0}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">SLA Breaches</CardTitle>
          </CardHeader>
          <CardContent className="text-3xl font-bold" data-testid="stat-breaches">
            {breaches.data?.breaches.length ?? 0}
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="workload">
        <TabsList>
          <TabsTrigger value="workload">Workload</TabsTrigger>
          <TabsTrigger value="breaches">SLA Breaches</TabsTrigger>
          <TabsTrigger value="my-queue">My Queue</TabsTrigger>
          <TabsTrigger value="sla">SLA Config</TabsTrigger>
        </TabsList>

        <TabsContent value="workload">
          <Card>
            <CardHeader>
              <CardTitle>Admin Workload</CardTitle>
            </CardHeader>
            <CardContent>
              <Table data-testid="workload-table">
                <TableHeader>
                  <TableRow>
                    <TableHead>Admin</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Cases</TableHead>
                    <TableHead>Avg Time (h)</TableHead>
                    <TableHead>Expertise</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {admins.map((a) => (
                    <TableRow key={a.admin_sub} data-testid={`admin-row-${a.admin_sub}`}>
                      <TableCell>{a.admin_sub}</TableCell>
                      <TableCell>
                        <Badge variant={a.on_duty ? "default" : "secondary"}>
                          {a.on_duty ? "On duty" : "Off duty"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {a.current_case_count}/{a.max_cases}
                      </TableCell>
                      <TableCell>{a.avg_processing_hours}</TableCell>
                      <TableCell>
                        {a.expertise_tiers.map((t) => (
                          <Badge key={t} variant="outline" className="mr-1">
                            {t}
                          </Badge>
                        ))}
                      </TableCell>
                    </TableRow>
                  ))}
                  {admins.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-muted-foreground">
                        No admin availability configured.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="breaches">
          <Card>
            <CardHeader>
              <CardTitle>SLA-Breached Cases</CardTitle>
            </CardHeader>
            <CardContent>
              <Table data-testid="breach-table">
                <TableHeader>
                  <TableRow>
                    <TableHead>Case</TableHead>
                    <TableHead>Tier</TableHead>
                    <TableHead>Assignee</TableHead>
                    <TableHead>Hours Overdue</TableHead>
                    <TableHead>Level</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(breaches.data?.breaches ?? []).map((b) => (
                    <TableRow key={b.kyc_case_id}>
                      <TableCell>{b.kyc_case_id}</TableCell>
                      <TableCell>{b.tier}</TableCell>
                      <TableCell>{b.assigned_admin_sub}</TableCell>
                      <TableCell>{b.hours_overdue}</TableCell>
                      <TableCell>{b.escalation_level}</TableCell>
                      <TableCell className="space-x-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => escalateMut.mutate(b.kyc_case_id)}
                        >
                          Escalate
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => setReassignCaseId(b.kyc_case_id)}
                        >
                          Reassign
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {(breaches.data?.breaches.length ?? 0) === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-muted-foreground">
                        No SLA breaches.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="my-queue">
          <Card>
            <CardHeader>
              <CardTitle>My Assigned Cases</CardTitle>
            </CardHeader>
            <CardContent>
              <Table data-testid="my-queue-table">
                <TableHeader>
                  <TableRow>
                    <TableHead>Case</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Tier</TableHead>
                    <TableHead>SLA Due</TableHead>
                    <TableHead>Overdue</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(myQueue.data?.cases ?? []).map((c) => (
                    <TableRow key={c.kyc_case_id}>
                      <TableCell>{c.kyc_case_id}</TableCell>
                      <TableCell>{c.status}</TableCell>
                      <TableCell>{c.tier}</TableCell>
                      <TableCell>
                        {c.sla_due_at
                          ? new Date(c.sla_due_at * 1000).toLocaleString()
                          : "—"}
                      </TableCell>
                      <TableCell>
                        {c.overdue ? (
                          <Badge variant="destructive">Overdue</Badge>
                        ) : (
                          <Badge variant="secondary">OK</Badge>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                  {(myQueue.data?.cases.length ?? 0) === 0 && (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-muted-foreground">
                        No cases assigned to you.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="sla">
          <Card>
            <CardHeader>
              <CardTitle>SLA Configuration (root only)</CardTitle>
            </CardHeader>
            <CardContent>
              <Table data-testid="sla-config-table">
                <TableHeader>
                  <TableRow>
                    <TableHead>Tier</TableHead>
                    <TableHead>Target Hours</TableHead>
                    <TableHead>Warning %</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {SLA_TIERS.map((tier) => {
                    const config = sla[tier] ?? { target_hours: 0, warning_pct: 0 };
                    return <SlaConfigRow key={tier} tier={tier} config={config} />;
                  })}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {reassignCaseId && (
        <ReassignDialog
          caseId={reassignCaseId}
          admins={admins}
          onClose={() => setReassignCaseId(null)}
        />
      )}
    </div>
  );
}
