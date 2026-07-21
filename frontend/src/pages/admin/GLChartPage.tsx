import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { BookOpen, Plus, Ban, RotateCcw } from "lucide-react";
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
import { StatusBadge } from "@/components/shared/StatusBadge";
import { EmptyState } from "@/components/shared/EmptyState";
import { Skeleton } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/shared/PageHeader";
import { ErrorPage } from "@/components/shared/ErrorPage";
import { ApiError } from "@/api/client";
import { toast } from "sonner";
import {
  listGLAccounts,
  createGLAccount,
  disableGLAccount,
  enableGLAccount,
  type GLAccount,
} from "@/api/endpoints/erpFinance";

const ACCOUNT_CLASSES = ["asset", "liability", "equity", "revenue", "expense", "contra_asset"];

export default function GLChartPage() {
  const queryClient = useQueryClient();
  const [classFilter, setClassFilter] = useState<string>("all");
  const [activeOnly, setActiveOnly] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({ account_code: "", name: "", account_class: "asset", description: "" });

  const query = useQuery({
    queryKey: ["gl", "accounts", { classFilter, activeOnly }],
    queryFn: () => listGLAccounts(classFilter === "all" ? undefined : classFilter, activeOnly),
    staleTime: 30_000,
    retry: (count, err) => !(err instanceof ApiError && err.status === 403) && count < 2,
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["gl", "accounts"] });

  const createMut = useMutation({
    mutationFn: () =>
      createGLAccount({
        account_code: form.account_code.trim(),
        name: form.name.trim(),
        account_class: form.account_class,
        description: form.description.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success("Account created");
      setCreateOpen(false);
      setForm({ account_code: "", name: "", account_class: "asset", description: "" });
      invalidate();
    },
    onError: (err: unknown) => toast.error(err instanceof ApiError ? err.detail : "Create failed"),
  });

  const disableMut = useMutation({
    mutationFn: (code: string) => disableGLAccount(code),
    onSuccess: () => { toast.success("Account disabled"); invalidate(); },
    onError: (err: unknown) => toast.error(err instanceof ApiError ? err.detail : "Disable failed"),
  });

  const enableMut = useMutation({
    mutationFn: (code: string) => enableGLAccount(code),
    onSuccess: () => { toast.success("Account enabled"); invalidate(); },
    onError: (err: unknown) => toast.error(err instanceof ApiError ? err.detail : "Enable failed"),
  });

  if (query.error instanceof ApiError && query.error.status === 403) {
    return (
      <ErrorPage
        status={403}
        title="Operator access required"
        description="The GL chart of accounts is available only to finance operators."
      />
    );
  }

  const accounts = query.data?.accounts ?? [];

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="GL Chart of Accounts"
        description="General-ledger account definitions (double-entry ERP)"
        actions={
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="mr-1 h-3.5 w-3.5" /> New Account
          </Button>
        }
      />

      <div className="flex flex-wrap items-center gap-2">
        <Select value={classFilter} onValueChange={setClassFilter}>
          <SelectTrigger className="w-44"><SelectValue placeholder="Class" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All classes</SelectItem>
            {ACCOUNT_CLASSES.map((c) => (
              <SelectItem key={c} value={c} className="capitalize">{c.replace(/_/g, " ")}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button
          size="sm"
          variant={activeOnly ? "default" : "outline"}
          onClick={() => setActiveOnly((v) => !v)}
        >
          {activeOnly ? "Active only" : "All (incl. disabled)"}
        </Button>
      </div>

      {query.isLoading && (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
        </div>
      )}

      {!query.isLoading && accounts.length === 0 && (
        <EmptyState icon={<BookOpen className="h-6 w-6" />} title="No accounts" description="No GL accounts match this filter." />
      )}

      {accounts.length > 0 && (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Code</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Class</TableHead>
                  <TableHead>Normal</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {accounts.map((a: GLAccount) => (
                  <TableRow key={a.account_code}>
                    <TableCell className="font-mono text-xs">{a.account_code}</TableCell>
                    <TableCell>
                      {a.name}
                      {a.is_system && <span className="ml-1 text-xs text-muted-foreground">(system)</span>}
                    </TableCell>
                    <TableCell className="capitalize">{a.account_class.replace(/_/g, " ")}</TableCell>
                    <TableCell className="capitalize">{a.normal_balance}</TableCell>
                    <TableCell>
                      <StatusBadge variant={a.is_active ? "success" : "neutral"}>
                        {a.is_active ? "active" : "disabled"}
                      </StatusBadge>
                    </TableCell>
                    <TableCell className="text-right">
                      {a.is_active ? (
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={a.is_system || disableMut.isPending}
                          onClick={() => disableMut.mutate(a.account_code)}
                        >
                          <Ban className="mr-1 h-3.5 w-3.5" /> Disable
                        </Button>
                      ) : (
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={enableMut.isPending}
                          onClick={() => enableMut.mutate(a.account_code)}
                        >
                          <RotateCcw className="mr-1 h-3.5 w-3.5" /> Enable
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>New GL Account</DialogTitle></DialogHeader>
          <div className="space-y-3 py-2">
            <div className="space-y-1.5">
              <Label htmlFor="acct-code">Account code</Label>
              <Input id="acct-code" placeholder="e.g. 6200" value={form.account_code}
                onChange={(e) => setForm({ ...form, account_code: e.target.value })} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="acct-name">Name</Label>
              <Input id="acct-name" placeholder="Account name" value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </div>
            <div className="space-y-1.5">
              <Label>Class</Label>
              <Select value={form.account_class} onValueChange={(v) => setForm({ ...form, account_class: v })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {ACCOUNT_CLASSES.map((c) => (
                    <SelectItem key={c} value={c} className="capitalize">{c.replace(/_/g, " ")}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="acct-desc">Description</Label>
              <Textarea id="acct-desc" rows={2} value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button
              onClick={() => createMut.mutate()}
              disabled={!form.account_code.trim() || !form.name.trim() || createMut.isPending}
            >
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
