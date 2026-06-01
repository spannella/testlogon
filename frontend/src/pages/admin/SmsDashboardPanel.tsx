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
  addSmsSuppression,
  getSmsDashboardStats,
  getSmsDeliveries,
  getSmsFailures,
  getSmsFailureTypes,
  getSmsSuppressions,
  getSmsTimeseries,
  removeSmsSuppression,
  sendTestSms,
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

export default function SmsDashboardPanel({ days = 7 }: { days?: number }) {
  const qc = useQueryClient();
  const [showAdd, setShowAdd] = useState(false);
  const [addr, setAddr] = useState("");
  const [reason, setReason] = useState("");
  const [showSend, setShowSend] = useState(false);
  const [testPhone, setTestPhone] = useState("");
  const [testBody, setTestBody] = useState("Test SMS from admin console");

  const stats = useQuery({
    queryKey: ["admin-sms", "stats", days],
    queryFn: () => getSmsDashboardStats(days),
    staleTime: 30_000,
  });
  const timeseries = useQuery({
    queryKey: ["admin-sms", "timeseries", days],
    queryFn: () => getSmsTimeseries(days),
    staleTime: 30_000,
  });
  const deliveries = useQuery({
    queryKey: ["admin-sms", "deliveries"],
    queryFn: () => getSmsDeliveries(20),
    staleTime: 10_000,
  });
  const failures = useQuery({
    queryKey: ["admin-sms", "failures"],
    queryFn: () => getSmsFailures(20),
    staleTime: 10_000,
  });
  const failureTypes = useQuery({
    queryKey: ["admin-sms", "failure-types", days],
    queryFn: () => getSmsFailureTypes(days),
    staleTime: 30_000,
  });
  const suppressions = useQuery({
    queryKey: ["admin-sms", "suppressed"],
    queryFn: () => getSmsSuppressions(),
    staleTime: 60_000,
  });

  const addMut = useMutation({
    mutationFn: () => addSmsSuppression(addr, reason || "manual"),
    onSuccess: () => {
      toast.success("SMS suppression added");
      setShowAdd(false);
      setAddr("");
      setReason("");
      qc.invalidateQueries({ queryKey: ["admin-sms", "suppressed"] });
    },
    onError: () => toast.error("Failed to add SMS suppression"),
  });

  const removeMut = useMutation({
    mutationFn: (phone: string) => removeSmsSuppression(phone),
    onSuccess: () => {
      toast.success("SMS suppression removed");
      qc.invalidateQueries({ queryKey: ["admin-sms", "suppressed"] });
    },
    onError: () => toast.error("Failed to remove SMS suppression"),
  });

  const sendTestMut = useMutation({
    mutationFn: () => sendTestSms(testPhone, testBody || "Test SMS from admin console"),
    onSuccess: (res) => {
      toast.success(`Test SMS: ${res.status}`);
      setShowSend(false);
      setTestPhone("");
      qc.invalidateQueries({ queryKey: ["admin-sms"] });
    },
    onError: () => toast.error("Failed to send test SMS"),
  });

  const s = stats.data;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-end">
        <Button size="sm" onClick={() => setShowSend(true)} data-testid="sms-send-test">
          Send test SMS
        </Button>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Sent (7d)" value={s?.sent ?? "—"} testid="kpi-sms-sent" />
        <KpiCard title="Delivery Rate" value={s ? `${s.delivery_rate}%` : "—"} testid="kpi-sms-delivery" />
        <KpiCard title="Failure Rate" value={s ? `${s.failure_rate}%` : "—"} variant="danger" testid="kpi-sms-failure" />
        <KpiCard title="Total Segments" value={s?.total_segments ?? "—"} testid="kpi-sms-segments" />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>SMS Delivery Trend</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Date</TableHead>
                <TableHead>Sent</TableHead>
                <TableHead>Failed</TableHead>
                <TableHead>Segments</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(timeseries.data?.points ?? []).map((p) => (
                <TableRow key={p.date}>
                  <TableCell>{p.date}</TableCell>
                  <TableCell>{p.sent}</TableCell>
                  <TableCell>{p.failed}</TableCell>
                  <TableCell>{p.segments}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Recent Failures</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Phone</TableHead>
                  <TableHead>Error</TableHead>
                  <TableHead>When</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(failures.data?.items ?? []).map((f, i) => (
                  <TableRow key={i}>
                    <TableCell>{f.phone ?? "—"}</TableCell>
                    <TableCell className="max-w-[220px] truncate">{f.error ?? "—"}</TableCell>
                    <TableCell>{fmtTs(f.created_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Failure Types</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Error Type</TableHead>
                  <TableHead>Count</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(failureTypes.data?.items ?? []).map((d) => (
                  <TableRow key={d.key}>
                    <TableCell className="max-w-[260px] truncate">{d.label}</TableCell>
                    <TableCell>{d.count}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent Deliveries</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Phone</TableHead>
                <TableHead>Segments</TableHead>
                <TableHead>When</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(deliveries.data?.items ?? []).map((d, i) => (
                <TableRow key={i}>
                  <TableCell>{d.phone ?? "—"}</TableCell>
                  <TableCell>{d.segments ?? "—"}</TableCell>
                  <TableCell>{fmtTs(d.created_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>SMS Suppression List</CardTitle>
          <Button size="sm" onClick={() => setShowAdd(true)} data-testid="sms-add-suppression">
            Add
          </Button>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Phone</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead>When</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {(suppressions.data?.items ?? []).map((row, i) => (
                <TableRow key={i}>
                  <TableCell>{row.phone ?? "—"}</TableCell>
                  <TableCell>{row.reason ?? "—"}</TableCell>
                  <TableCell>{fmtTs(row.suppressed_at)}</TableCell>
                  <TableCell>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => row.phone && removeMut.mutate(row.phone)}
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
            <DialogTitle>Add SMS Suppression</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="sms-supp-addr">Phone (E.164)</Label>
              <Input
                id="sms-supp-addr"
                value={addr}
                onChange={(e) => setAddr(e.target.value)}
                placeholder="+15551234567"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="sms-supp-reason">Reason</Label>
              <Input
                id="sms-supp-reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="opt-out"
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              onClick={() => addMut.mutate()}
              disabled={!addr || addMut.isPending}
              data-testid="sms-suppression-submit"
            >
              Add
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={showSend} onOpenChange={setShowSend}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Send Test SMS</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="sms-test-phone">Phone (E.164)</Label>
              <Input
                id="sms-test-phone"
                value={testPhone}
                onChange={(e) => setTestPhone(e.target.value)}
                placeholder="+15551234567"
                data-testid="sms-test-phone"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="sms-test-body">Message</Label>
              <Input
                id="sms-test-body"
                value={testBody}
                onChange={(e) => setTestBody(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              onClick={() => sendTestMut.mutate()}
              disabled={!testPhone || sendTestMut.isPending}
              data-testid="sms-send-test-submit"
            >
              Send
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
