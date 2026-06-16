import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Boxes, Plus, RefreshCcw } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { ApiError } from "@/api/client";
import {
  createAsset,
  listAssets,
  type FixedAsset,
} from "@/api/endpoints/fixedAssets";
import { FixedAssetDetail } from "./FixedAssetDetail";
import {
  dateInputToTs,
  dollarsToCents,
  fmtCents,
  fmtTs,
  prettyStatus,
  statusVariant,
} from "./lib";

const STATUS_FILTERS = ["", "active", "fully_depreciated", "disposed"] as const;

export default function FixedAssetsPage() {
  const qc = useQueryClient();
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);

  const listQuery = useQuery({
    queryKey: ["fixed-assets", "list", { statusFilter, cursor }],
    queryFn: () =>
      listAssets({
        status: statusFilter || undefined,
        cursor,
        limit: 50,
      }),
    retry: false,
  });

  const featureDisabled =
    listQuery.error instanceof ApiError &&
    (listQuery.error.status === 404 || listQuery.error.status === 503);

  const assets = listQuery.data?.items ?? [];

  // Create form state
  const [name, setName] = useState("");
  const [assetClass, setAssetClass] = useState("");
  const [cost, setCost] = useState("");
  const [salvage, setSalvage] = useState("");
  const [life, setLife] = useState("");
  const [acquired, setAcquired] = useState(
    new Date().toISOString().slice(0, 10),
  );

  const resetForm = () => {
    setName("");
    setAssetClass("");
    setCost("");
    setSalvage("");
    setLife("");
    setAcquired(new Date().toISOString().slice(0, 10));
  };

  const createMut = useMutation({
    mutationFn: () =>
      createAsset({
        name: name.trim(),
        asset_class: assetClass.trim(),
        acquisition_cost_cents: dollarsToCents(cost),
        salvage_value_cents: dollarsToCents(salvage),
        useful_life_months: parseInt(life, 10) || 0,
        acquired_at: dateInputToTs(acquired),
      }),
    onSuccess: (asset) => {
      toast.success("Asset created");
      setCreateOpen(false);
      resetForm();
      setSelectedId(asset.asset_id);
      void qc.invalidateQueries({ queryKey: ["fixed-assets", "list"] });
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to create asset"),
  });

  const canCreate =
    name.trim() &&
    assetClass.trim() &&
    dollarsToCents(cost) > 0 &&
    parseInt(life, 10) > 0 &&
    dollarsToCents(salvage) < dollarsToCents(cost);

  if (selectedId) {
    return (
      <FixedAssetDetail
        assetId={selectedId}
        onBack={() => {
          setSelectedId(null);
          void listQuery.refetch();
        }}
      />
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Fixed Assets"
        description="Asset register, depreciation, disposal and maintenance (admin)"
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => void listQuery.refetch()}
              disabled={listQuery.isFetching}
            >
              <RefreshCcw className="mr-2 h-4 w-4" />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="mr-2 h-4 w-4" />
              New asset
            </Button>
          </div>
        }
      />

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <div>
            <CardTitle>Asset register</CardTitle>
            <CardDescription>
              Net book value = acquisition cost − accumulated depreciation
            </CardDescription>
          </div>
          <Select
            value={statusFilter || "all"}
            onValueChange={(v) => {
              setStatusFilter(v === "all" ? "" : v);
              setCursor(undefined);
            }}
          >
            <SelectTrigger className="w-44" aria-label="Status filter">
              <SelectValue placeholder="All statuses" />
            </SelectTrigger>
            <SelectContent>
              {STATUS_FILTERS.map((s) => (
                <SelectItem key={s || "all"} value={s || "all"}>
                  {s ? prettyStatus(s) : "All statuses"}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </CardHeader>
        <CardContent>
          {listQuery.isLoading ? (
            <p className="py-8 text-center text-sm text-muted-foreground">Loading assets…</p>
          ) : featureDisabled ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              The fixed-assets module is not enabled.
            </p>
          ) : assets.length === 0 ? (
            <div className="flex flex-col items-center gap-2 py-12 text-center">
              <Boxes className="h-10 w-10 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">No assets in the register yet.</p>
              <Button size="sm" variant="outline" onClick={() => setCreateOpen(true)}>
                <Plus className="mr-2 h-4 w-4" />
                Add your first asset
              </Button>
            </div>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Class</TableHead>
                    <TableHead className="text-right">Cost</TableHead>
                    <TableHead className="text-right">Accum. depr.</TableHead>
                    <TableHead className="text-right">Net book value</TableHead>
                    <TableHead>Acquired</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assets.map((a: FixedAsset) => (
                    <TableRow
                      key={a.asset_id}
                      className="cursor-pointer"
                      onClick={() => setSelectedId(a.asset_id)}
                    >
                      <TableCell className="font-medium">{a.name}</TableCell>
                      <TableCell>{a.asset_class}</TableCell>
                      <TableCell className="text-right tabular-nums">
                        {fmtCents(a.acquisition_cost_cents)}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">
                        {fmtCents(a.accumulated_depreciation_cents)}
                      </TableCell>
                      <TableCell className="text-right font-medium tabular-nums">
                        {fmtCents(a.net_book_value_cents)}
                      </TableCell>
                      <TableCell>{fmtTs(a.acquired_at)}</TableCell>
                      <TableCell>
                        <Badge variant={statusVariant(a.status)}>
                          {prettyStatus(a.status)}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {listQuery.data?.cursor && (
                <div className="mt-4 flex justify-center">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setCursor(listQuery.data?.cursor ?? undefined)}
                  >
                    Load more
                  </Button>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New fixed asset</DialogTitle>
            <DialogDescription>
              Register an asset. A straight-line depreciation schedule can be generated afterward.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-2">
            <div className="grid gap-2">
              <Label htmlFor="fa-name">Name</Label>
              <Input
                id="fa-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Server rack #3"
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="fa-class">Asset class</Label>
              <Input
                id="fa-class"
                value={assetClass}
                onChange={(e) => setAssetClass(e.target.value)}
                placeholder="hardware"
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="fa-cost">Acquisition cost ($)</Label>
                <Input
                  id="fa-cost"
                  value={cost}
                  onChange={(e) => setCost(e.target.value)}
                  placeholder="12000.00"
                  inputMode="decimal"
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="fa-salvage">Salvage value ($)</Label>
                <Input
                  id="fa-salvage"
                  value={salvage}
                  onChange={(e) => setSalvage(e.target.value)}
                  placeholder="500.00"
                  inputMode="decimal"
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="fa-life">Useful life (months)</Label>
                <Input
                  id="fa-life"
                  value={life}
                  onChange={(e) => setLife(e.target.value)}
                  placeholder="36"
                  inputMode="numeric"
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="fa-acquired">Acquired</Label>
                <Input
                  id="fa-acquired"
                  type="date"
                  value={acquired}
                  onChange={(e) => setAcquired(e.target.value)}
                />
              </div>
            </div>
            {dollarsToCents(salvage) >= dollarsToCents(cost) && cost && salvage && (
              <p className="text-xs text-destructive">
                Salvage value must be less than acquisition cost.
              </p>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => createMut.mutate()}
              disabled={!canCreate || createMut.isPending}
            >
              {createMut.isPending ? "Creating…" : "Create asset"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
