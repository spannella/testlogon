import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { FileSignature, Loader2, Plus } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ApiError } from "@/api/client";
import { createContract, listContracts, type ContractStage } from "@/api/endpoints/quotes";
import { NotEnabledCard } from "./NotEnabledCard";
import {
  CONTRACT_STAGES,
  contractStageVariant,
  dateInputToTs,
  fmtDate,
  formatCents,
  isNotEnabled,
  parseDollarsToCents,
} from "./quotesUtils";

export default function ContractsPage() {
  const qc = useQueryClient();
  const [stageFilter, setStageFilter] = useState<"all" | ContractStage>("all");
  const [createOpen, setCreateOpen] = useState(false);

  const contractsQuery = useQuery({
    queryKey: ["contracts", "list", stageFilter],
    queryFn: () =>
      listContracts({ stage: stageFilter === "all" ? undefined : stageFilter, limit: 100 }),
    retry: false,
  });

  const [title, setTitle] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [valueInput, setValueInput] = useState("0.00");
  const [currency, setCurrency] = useState("usd");
  const [renewalDays, setRenewalDays] = useState(30);
  const [description, setDescription] = useState("");

  const resetForm = () => {
    setTitle("");
    setStartDate("");
    setEndDate("");
    setValueInput("0.00");
    setCurrency("usd");
    setRenewalDays(30);
    setDescription("");
  };

  const createMut = useMutation({
    mutationFn: () => {
      const start = dateInputToTs(startDate);
      if (start === null) throw new ApiError(400, "A start date is required");
      return createContract({
        title: title.trim(),
        start_date: start,
        end_date: dateInputToTs(endDate),
        value_cents: parseDollarsToCents(valueInput),
        currency: currency.trim() || "usd",
        renewal_notice_days: Math.max(1, Math.min(365, renewalDays || 30)),
        description: description.trim(),
      });
    },
    onSuccess: () => {
      toast.success("Contract created");
      setCreateOpen(false);
      resetForm();
      qc.invalidateQueries({ queryKey: ["contracts"] });
    },
    onError: (e) => toast.error(e instanceof ApiError ? e.detail : "Failed to create contract"),
  });

  const canSubmit = title.trim().length > 0 && startDate.length > 0 && !createMut.isPending;

  if (contractsQuery.isError && isNotEnabled(contractsQuery.error)) {
    return (
      <div className="space-y-6">
        <PageHeader title="Contracts" description="CRM contracts & renewals" />
        <NotEnabledCard feature="Contracts" />
      </div>
    );
  }

  const contracts = contractsQuery.data?.contracts ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Contracts"
        description="Track signed contracts, value, and renewal windows."
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="mr-1 h-4 w-4" /> New contract
          </Button>
        }
      />

      <div className="flex items-center gap-2">
        <Label htmlFor="c-stage-filter" className="text-sm text-muted-foreground">
          Stage
        </Label>
        <Select
          value={stageFilter}
          onValueChange={(v) => setStageFilter(v as "all" | ContractStage)}
        >
          <SelectTrigger id="c-stage-filter" className="w-44">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All stages</SelectItem>
            {CONTRACT_STAGES.map((s) => (
              <SelectItem key={s} value={s} className="capitalize">
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {contractsQuery.isLoading ? (
        <Card>
          <CardContent className="flex items-center justify-center py-16">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </CardContent>
        </Card>
      ) : contracts.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center gap-3 py-16 text-center">
            <FileSignature className="h-10 w-10 text-muted-foreground" />
            <div className="text-lg font-medium">No contracts yet</div>
            <p className="text-sm text-muted-foreground">
              Create a contract or convert an accepted quote.
            </p>
            <Button onClick={() => setCreateOpen(true)}>
              <Plus className="mr-1 h-4 w-4" /> New contract
            </Button>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Number</TableHead>
                  <TableHead>Title</TableHead>
                  <TableHead>Stage</TableHead>
                  <TableHead className="text-right">Value</TableHead>
                  <TableHead>Start</TableHead>
                  <TableHead>End</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {contracts.map((c) => (
                  <TableRow key={c.contract_id}>
                    <TableCell className="font-mono text-xs">
                      <Link className="hover:underline" to={`/crm/contracts/${c.contract_id}`}>
                        {c.contract_number || c.contract_id}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <Link
                        className="font-medium hover:underline"
                        to={`/crm/contracts/${c.contract_id}`}
                      >
                        {c.title}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <Badge variant={contractStageVariant(c.stage)} className="capitalize">
                        {c.stage}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatCents(c.value_cents, c.currency)}
                    </TableCell>
                    <TableCell>{fmtDate(c.start_date)}</TableCell>
                    <TableCell>{fmtDate(c.end_date)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <Dialog open={createOpen} onOpenChange={(o) => setCreateOpen(o)}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>New contract</DialogTitle>
          </DialogHeader>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1 sm:col-span-2">
              <Label htmlFor="ct-title">Title</Label>
              <Input id="ct-title" value={title} onChange={(e) => setTitle(e.target.value)} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="ct-start">Start date</Label>
              <Input
                id="ct-start"
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="ct-end">End date</Label>
              <Input
                id="ct-end"
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="ct-value">Value</Label>
              <Input
                id="ct-value"
                inputMode="decimal"
                value={valueInput}
                onChange={(e) => setValueInput(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="ct-currency">Currency</Label>
              <Input
                id="ct-currency"
                value={currency}
                onChange={(e) => setCurrency(e.target.value)}
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="ct-renewal">Renewal notice (days)</Label>
              <Input
                id="ct-renewal"
                type="number"
                min={1}
                max={365}
                value={renewalDays}
                onChange={(e) => setRenewalDays(Number(e.target.value))}
              />
            </div>
            <div className="space-y-1 sm:col-span-2">
              <Label htmlFor="ct-desc">Description</Label>
              <Textarea
                id="ct-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button disabled={!canSubmit} onClick={() => createMut.mutate()}>
              {createMut.isPending && <Loader2 className="mr-1 h-4 w-4 animate-spin" />}
              Create contract
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
