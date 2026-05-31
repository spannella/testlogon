import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  addEmailSuppression,
  getEmailBounceDomains,
  getEmailBounces,
  getEmailComplaints,
  getEmailDashboardStats,
  getEmailDeliveries,
  getEmailSuppressions,
  getEmailTimeseries,
  removeEmailSuppression,
} from "@/api/endpoints/adminMessagingDashboards";

function KpiCard({
  title,
  value,
  variant = "default",
  testid,
}: {
  title: string;
  value: string | number;
  variant?: "default" | "warning" | "danger";
  testid?: string;
}) {
  const tone =
    variant === "danger"
      ? "text-red-600"
      : variant === "warning"
        ? "text-amber-600"
        : "text-foreground";
  return (
    <Card data-testid={testid}>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className={`text-2xl font-bold ${tone}`}>{value}</div>
      </CardContent>
    </Card>
  );
}

function fmtTs(ts?: number): string {
  if (!ts) return "—";
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch {
    return String(ts);
  }
}

export default function EmailDashboardPanel({ days = 7 }: { days?: number }) {
  const qc = useQueryClient();
  const [showAdd, setShowAdd] = useState(false);
  const [addr, setAddr] = useState("");
  const [reason, setReason] = useState("");

  const stats = useQuery({
    queryKey: ["admin-email", "stats", days],
    queryFn: () => getEmailDashboardStats(days),
    staleTime: 30_000,
  });
  const timeseries = useQuery({
    queryKey: ["admin-email", "timeseries", days],
    queryFn: () => getEmailTimeseries(days),
    staleTime: 30_000,
  });
  const bounces = useQuery({
    queryKey: ["admin-email", "bounces"],
    queryFn: () => getEmailBounces(20),
    staleTime: 10_000,
  });
  const complaints = useQuery({
    queryKey: ["admin-email", "complaints"],
    queryFn: () => getEmailComplaints(20),
    staleTime: 10_000,
  });
  const deliveries = useQuery({
    queryKey: ["admin-email", "deliveries"],
    queryFn: () => getEmailDeliveries(20),
    staleTime: 10_000,
  });
  const bounceDomains = useQuery({
    queryKey: ["admin-email", "bounce-domains", days],
    queryFn: () => getEmailBounceDomains(days),
    staleTime: 30_000,
  });
  const suppressions = useQuery({
    queryKey: ["admin-email", "suppressed"],
    queryFn: () => getEmailSuppressions(),
    staleTime: 60_000,
  });

  const addMut = useMutation({
    mutationFn: () => addEmailSuppression(addr, reason || "manual"),
    onSuccess: () => {
      toast.success("Suppression added");
      setShowAdd(false);
      setAddr("");
      setReason("");
      qc.invalidateQueries({ queryKey: ["admin-email", "suppressed"] });
    },
    onError: () => toast.error("Failed to add suppression"),
  });

  const removeMut = useMutation({
    mutationFn: (email: string) => removeEmailSuppression(email),
    onSuccess: () => {
      toast.success("Suppression removed");
      qc.invalidateQueries({ queryKey: ["admin-email", "suppressed"] });
    },
    onError: () => toast.error("Failed to remove suppression"),
  });

  const s = stats.data;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Sent (7d)" value={s?.sent ?? "—"} testid="kpi-email-sent" />
        <KpiCard title="Delivery Rate" value={s ? `${s.delivery_rate}%` : "—"} testid="kpi-email-delivery" />
        <KpiCard title="Bounce Rate" value={s ? `${s.bounce_rate}%` : "—"} variant="warning" testid="kpi-email-bounce" />
        <KpiCard title="Complaint Rate" value={s ? `${s.complaint_rate}%` : "—"} variant="danger" testid="kpi-email-complaint" />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Email Delivery Trend</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Date</TableHead>
                <TableHead>Sent</TableHead>
                <TableHead>Delivered</TableHead>
                <TableHead>Bounced</TableHead>
                <TableHead>Complained</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(timeseries.data?.points ?? []).map((p) => (
                <TableRow key={p.date}>
                  <TableCell>{p.date}</TableCell>
                  <TableCell>{p.sent}</TableCell>
                  <TableCell>{p.delivered}</TableCell>
                  <TableCell>{p.bounced}</TableCell>
                  <TableCell>{p.complained}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Recent Bounces</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Recipient</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>When</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(bounces.data?.items ?? []).map((b, i) => (
                  <TableRow key={i}>
                    <TableCell>{b.to_email ?? "—"}</TableCell>
                    <TableCell>{b.bounce_type ?? "—"}</TableCell>
                    <TableCell>{fmtTs(b.created_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Recent Complaints</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Recipient</TableHead>
                  <TableHead>Feedback</TableHead>
                  <TableHead>When</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(complaints.data?.items ?? []).map((c, i) => (
                  <TableRow key={i}>
                    <TableCell>{c.to_email ?? "—"}</TableCell>
                    <TableCell>{c.complaint_feedback_type ?? "—"}</TableCell>
                    <TableCell>{fmtTs(c.created_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Top Bouncing Domains</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Domain</TableHead>
                <TableHead>Bounces</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(bounceDomains.data?.items ?? []).map((d) => (
                <TableRow key={d.key}>
                  <TableCell>{d.label}</TableCell>
                  <TableCell>{d.count}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Email Suppression List</CardTitle>
          <Button size="sm" onClick={() => setShowAdd(true)} data-testid="email-add-suppression">
            Add
          </Button>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Address</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead>When</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {(suppressions.data?.items ?? []).map((row, i) => (
                <TableRow key={i}>
                  <TableCell>{row.email ?? "—"}</TableCell>
                  <TableCell>{row.reason ?? "—"}</TableCell>
                  <TableCell>{fmtTs(row.suppressed_at)}</TableCell>
                  <TableCell>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => row.email && removeMut.mutate(row.email)}
                    >
                      Remove
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={showAdd} onOpenChange={setShowAdd}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Email Suppression</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="email-supp-addr">Address</Label>
              <Input
                id="email-supp-addr"
                value={addr}
                onChange={(e) => setAddr(e.target.value)}
                placeholder="spam@example.com"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="email-supp-reason">Reason</Label>
              <Input
                id="email-supp-reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="manual"
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              onClick={() => addMut.mutate()}
              disabled={!addr || addMut.isPending}
              data-testid="email-suppression-submit"
            >
              Add
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
