import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Plus, Users } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EmptyState } from "@/components/shared/EmptyState";
import { ApiError } from "@/api/client";
import {
  createEmployment,
  listEmployments,
  listPositions,
  terminateEmployment,
  type Employment,
  type EmploymentStatus,
  type PayPeriod,
} from "@/api/endpoints/hr";
import { dateInputToTs, fmtCents, fmtDate, isFeatureDisabled, tsToDateInput } from "./hrShared";

const STATUS_FILTERS: Array<{ label: string; value: string }> = [
  { label: "All statuses", value: "" },
  { label: "Active", value: "ACTIVE" },
  { label: "On leave", value: "ON_LEAVE" },
  { label: "Terminated", value: "TERMINATED" },
];

const PAY_PERIODS: PayPeriod[] = ["MONTHLY", "BIWEEKLY", "WEEKLY", "HOURLY"];

function statusBadge(status: EmploymentStatus) {
  const variant =
    status === "ACTIVE" ? "success" : status === "ON_LEAVE" ? "warning" : "outline";
  return <Badge variant={variant as never}>{status.replace("_", " ")}</Badge>;
}

const todayInput = () => new Date().toISOString().slice(0, 10);

export function EmploymentsPanel({ onDisabled }: { onDisabled: () => void }) {
  const qc = useQueryClient();
  const [statusFilter, setStatusFilter] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [termTarget, setTermTarget] = useState<Employment | null>(null);
  const [termDate, setTermDate] = useState(todayInput());
  const [termNote, setTermNote] = useState("");

  // create form
  const [partyId, setPartyId] = useState("");
  const [positionId, setPositionId] = useState("");
  const [orgPartyId, setOrgPartyId] = useState("");
  const [startDate, setStartDate] = useState(todayInput());
  const [payRate, setPayRate] = useState("");
  const [payPeriod, setPayPeriod] = useState<PayPeriod>("MONTHLY");
  const [currency, setCurrency] = useState("USD");

  const employmentsQuery = useQuery({
    queryKey: ["hr", "employments", { statusFilter }],
    queryFn: () => listEmployments({ status: statusFilter || undefined, limit: 100 }),
    retry: false,
  });

  if (employmentsQuery.isError && isFeatureDisabled(employmentsQuery.error)) {
    onDisabled();
  }

  // Positions for the create dropdown (OPEN only — those can be filled).
  const positionsQuery = useQuery({
    queryKey: ["hr", "positions", "for-employment"],
    queryFn: () => listPositions({ limit: 200 }),
    retry: false,
    enabled: createOpen,
  });

  const createMut = useMutation({
    mutationFn: () =>
      createEmployment({
        party_id: partyId.trim(),
        position_id: positionId.trim(),
        org_party_id: orgPartyId.trim(),
        start_date: dateInputToTs(startDate),
        pay_rate_cents: Math.round(parseFloat(payRate || "0") * 100),
        pay_period: payPeriod,
        currency: currency.trim().toUpperCase(),
      }),
    onSuccess: () => {
      toast.success("Employment created");
      setCreateOpen(false);
      setPartyId("");
      setPositionId("");
      setOrgPartyId("");
      setPayRate("");
      qc.invalidateQueries({ queryKey: ["hr", "employments"] });
    },
    onError: (e) =>
      toast.error(e instanceof ApiError ? e.detail : "Failed to create employment"),
  });

  const terminateMut = useMutation({
    mutationFn: () =>
      terminateEmployment(termTarget!.employment_id, {
        end_date: dateInputToTs(termDate),
        note: termNote.trim() || null,
      }),
    onSuccess: () => {
      toast.success("Employment terminated");
      setTermTarget(null);
      setTermNote("");
      qc.invalidateQueries({ queryKey: ["hr", "employments"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to terminate"),
  });

  const employments: Employment[] = employmentsQuery.data?.items ?? [];
  const createValid =
    partyId.trim() && positionId.trim() && orgPartyId.trim() && startDate && payRate.trim();

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <Select
          value={statusFilter || "__all__"}
          onValueChange={(v) => setStatusFilter(v === "__all__" ? "" : v)}
        >
          <SelectTrigger className="w-48" aria-label="Filter employments by status">
            <SelectValue placeholder="All statuses" />
          </SelectTrigger>
          <SelectContent>
            {STATUS_FILTERS.map((f) => (
              <SelectItem key={f.value || "all"} value={f.value || "__all__"}>
                {f.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> New employment
        </Button>
      </div>

      <Card>
        <CardContent className="p-0">
          {employmentsQuery.isLoading ? (
            <div className="p-8 text-center text-sm text-muted-foreground">Loading employments…</div>
          ) : employments.length === 0 ? (
            <EmptyState
              icon={<Users className="h-10 w-10" />}
              title="No employments"
              description="Link a party to a position to create an employment record."
              action={{ label: "New employment", onClick: () => setCreateOpen(true) }}
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Party</TableHead>
                  <TableHead>Position</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Pay</TableHead>
                  <TableHead>Start</TableHead>
                  <TableHead>End</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {employments.map((e) => (
                  <TableRow key={e.employment_id}>
                    <TableCell className="font-mono text-xs">{e.party_id}</TableCell>
                    <TableCell className="font-mono text-xs">{e.position_id}</TableCell>
                    <TableCell>{statusBadge(e.status)}</TableCell>
                    <TableCell className="text-sm">
                      {fmtCents(e.pay_rate_cents, e.currency)}
                      <span className="text-muted-foreground"> / {e.pay_period.toLowerCase()}</span>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {fmtDate(e.start_date)}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {fmtDate(e.end_date)}
                    </TableCell>
                    <TableCell className="text-right">
                      {e.status === "TERMINATED" ? (
                        <span className="text-xs text-muted-foreground">—</span>
                      ) : (
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => {
                            setTermTarget(e);
                            setTermDate(tsToDateInput(e.end_date) || todayInput());
                            setTermNote("");
                          }}
                        >
                          Terminate
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Create dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New employment</DialogTitle>
            <DialogDescription>Link a party (person) to a position.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="emp-party">Party ID</Label>
              <Input
                id="emp-party"
                value={partyId}
                onChange={(ev) => setPartyId(ev.target.value)}
                placeholder="PERSON-..."
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="emp-position">Position</Label>
              <Select value={positionId} onValueChange={setPositionId}>
                <SelectTrigger id="emp-position">
                  <SelectValue placeholder="Select a position" />
                </SelectTrigger>
                <SelectContent>
                  {(positionsQuery.data?.items ?? []).map((p) => (
                    <SelectItem key={p.position_id} value={p.position_id}>
                      {p.title}
                      {p.department ? ` · ${p.department}` : ""} ({p.status})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="emp-org">Organization party ID</Label>
              <Input
                id="emp-org"
                value={orgPartyId}
                onChange={(ev) => setOrgPartyId(ev.target.value)}
                placeholder="ORG-..."
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="emp-start">Start date</Label>
                <Input
                  id="emp-start"
                  type="date"
                  value={startDate}
                  onChange={(ev) => setStartDate(ev.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="emp-currency">Currency</Label>
                <Input
                  id="emp-currency"
                  value={currency}
                  maxLength={3}
                  onChange={(ev) => setCurrency(ev.target.value.toUpperCase())}
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="emp-rate">Pay rate</Label>
                <Input
                  id="emp-rate"
                  type="number"
                  min="0"
                  step="0.01"
                  value={payRate}
                  onChange={(ev) => setPayRate(ev.target.value)}
                  placeholder="0.00"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="emp-period">Pay period</Label>
                <Select value={payPeriod} onValueChange={(v) => setPayPeriod(v as PayPeriod)}>
                  <SelectTrigger id="emp-period">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {PAY_PERIODS.map((p) => (
                      <SelectItem key={p} value={p}>
                        {p.charAt(0) + p.slice(1).toLowerCase()}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button onClick={() => createMut.mutate()} disabled={!createValid || createMut.isPending}>
              {createMut.isPending ? "Creating…" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Terminate dialog */}
      <Dialog open={!!termTarget} onOpenChange={(o) => !o && setTermTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Terminate employment</DialogTitle>
            <DialogDescription>
              End the employment record for party{" "}
              <span className="font-mono">{termTarget?.party_id}</span>.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="term-date">End date</Label>
              <Input
                id="term-date"
                type="date"
                value={termDate}
                onChange={(ev) => setTermDate(ev.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="term-note">Note (optional)</Label>
              <Textarea
                id="term-note"
                value={termNote}
                onChange={(ev) => setTermNote(ev.target.value)}
                maxLength={500}
                placeholder="Reason for termination…"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTermTarget(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => terminateMut.mutate()}
              disabled={!termDate || terminateMut.isPending}
            >
              {terminateMut.isPending ? "Terminating…" : "Terminate"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
