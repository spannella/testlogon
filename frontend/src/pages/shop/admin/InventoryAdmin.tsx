import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Loader2, Package, Search, AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EmptyState } from "@/components/shared/EmptyState";
import {
  getInventoryItem,
  setInventoryOnHand,
  adjustInventory,
  listLowStock,
} from "@/api/endpoints/inventory";
import { isInventoryReservationsEnabled } from "@/lib/featureFlags";
import { useAuthStore } from "@/stores/authStore";
import { canAccessGeneralAdminControls } from "@/lib/adminCapabilities";
import type { InventoryRecord } from "@/api/types";

function statusBadge(status: string) {
  if (status === "out_of_stock")
    return <Badge variant="destructive">Out of stock</Badge>;
  if (status === "low_stock")
    return (
      <Badge variant="outline" className="border-amber-500 text-amber-600">
        Low stock
      </Badge>
    );
  return (
    <Badge variant="outline" className="border-emerald-500 text-emerald-600">
      In stock
    </Badge>
  );
}

function InventoryRow({
  rec,
  onAdjust,
}: {
  rec: InventoryRecord;
  onAdjust: (sku: string, delta: number) => void;
}) {
  const [delta, setDelta] = useState("");
  return (
    <TableRow>
      <TableCell className="font-mono text-xs">{rec.sku}</TableCell>
      <TableCell className="tabular-nums">{rec.on_hand}</TableCell>
      <TableCell className="tabular-nums">{rec.reserved}</TableCell>
      <TableCell className="tabular-nums font-semibold">{rec.available}</TableCell>
      <TableCell className="tabular-nums">{rec.reorder_point}</TableCell>
      <TableCell>{statusBadge(rec.status)}</TableCell>
      <TableCell>
        <div className="flex items-center gap-1">
          <Input
            type="number"
            value={delta}
            onChange={(e) => setDelta(e.target.value)}
            placeholder="±qty"
            className="h-8 w-20"
          />
          <Button
            size="sm"
            variant="outline"
            disabled={!delta || Number.isNaN(Number(delta)) || Number(delta) === 0}
            onClick={() => {
              onAdjust(rec.sku, Number(delta));
              setDelta("");
            }}
          >
            Apply
          </Button>
        </div>
      </TableCell>
    </TableRow>
  );
}

export function InventoryAdmin() {
  const qc = useQueryClient();
  const accessToken = useAuthStore((s) => s.accessToken);
  const allowed = canAccessGeneralAdminControls(accessToken);

  const [skuQuery, setSkuQuery] = useState("");
  const [loadedSku, setLoadedSku] = useState<string | null>(null);

  // Set-on-hand form
  const [onHandValue, setOnHandValue] = useState("");
  const [reorderValue, setReorderValue] = useState("");

  const lowStockQuery = useQuery({
    queryKey: ["inventory", "low-stock"],
    queryFn: () => listLowStock("low_stock"),
    enabled: allowed,
  });

  const lookupQuery = useQuery({
    queryKey: ["inventory", "item", loadedSku],
    queryFn: () => getInventoryItem(loadedSku as string),
    enabled: allowed && !!loadedSku,
    retry: false,
  });

  const setOnHandMut = useMutation({
    mutationFn: async () => {
      const sku = loadedSku ?? skuQuery.trim();
      const body: {
        sku: string;
        on_hand: number;
        reorder_point?: number;
      } = { sku, on_hand: Number(onHandValue) };
      if (reorderValue !== "" && !Number.isNaN(Number(reorderValue))) {
        body.reorder_point = Number(reorderValue);
      }
      return setInventoryOnHand(body);
    },
    onSuccess: (rec) => {
      toast.success(`Set ${rec.sku} on-hand to ${rec.on_hand}`);
      setLoadedSku(rec.sku);
      setOnHandValue("");
      setReorderValue("");
      qc.invalidateQueries({ queryKey: ["inventory"] });
    },
    onError: () => toast.error("Failed to set on-hand quantity"),
  });

  const adjustMut = useMutation({
    mutationFn: ({ sku, delta }: { sku: string; delta: number }) =>
      adjustInventory({ sku, delta, reason: "manual_adjust" }),
    onSuccess: (rec) => {
      toast.success(`Adjusted ${rec.sku} — available now ${rec.available}`);
      qc.invalidateQueries({ queryKey: ["inventory"] });
    },
    onError: () => toast.error("Adjustment failed (insufficient stock?)"),
  });

  if (!isInventoryReservationsEnabled()) {
    return (
      <div className="p-6">
        <EmptyState
          icon={<Package className="h-10 w-10" />}
          title="Inventory management is not enabled"
          description="Enable the inventory & reservations feature flag to manage stock levels."
        />
      </div>
    );
  }

  if (!allowed) {
    return (
      <div className="p-6">
        <EmptyState
          icon={<AlertTriangle className="h-10 w-10" />}
          title="Access denied"
          description="Inventory management requires admin or root access."
        />
      </div>
    );
  }

  const handleLookup = () => {
    const sku = skuQuery.trim();
    if (sku) setLoadedSku(sku);
  };

  const lookupRec = lookupQuery.data;

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center gap-2">
        <Package className="h-6 w-6" />
        <h1 className="text-2xl font-semibold tracking-tight">Inventory</h1>
      </div>

      {/* Lookup + manage a single SKU */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Manage SKU</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-end gap-2">
            <div className="flex-1">
              <Label htmlFor="sku-lookup">SKU</Label>
              <Input
                id="sku-lookup"
                value={skuQuery}
                onChange={(e) => setSkuQuery(e.target.value)}
                placeholder="Enter a SKU / item id"
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleLookup();
                }}
              />
            </div>
            <Button onClick={handleLookup} disabled={!skuQuery.trim()}>
              <Search className="mr-1 h-4 w-4" /> Look up
            </Button>
          </div>

          {loadedSku && lookupQuery.isLoading && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading {loadedSku}…
            </div>
          )}

          {loadedSku && !lookupQuery.isLoading && !lookupRec && (
            <p className="text-sm text-muted-foreground">
              No inventory record for{" "}
              <span className="font-mono">{loadedSku}</span> yet. Set an on-hand
              quantity below to create one.
            </p>
          )}

          {lookupRec && (
            <div className="grid grid-cols-2 gap-3 rounded-md border p-3 text-sm sm:grid-cols-5">
              <div>
                <div className="text-muted-foreground">On hand</div>
                <div className="text-lg font-semibold tabular-nums">
                  {lookupRec.on_hand}
                </div>
              </div>
              <div>
                <div className="text-muted-foreground">Reserved</div>
                <div className="text-lg font-semibold tabular-nums">
                  {lookupRec.reserved}
                </div>
              </div>
              <div>
                <div className="text-muted-foreground">Available</div>
                <div className="text-lg font-semibold tabular-nums">
                  {lookupRec.available}
                </div>
              </div>
              <div>
                <div className="text-muted-foreground">Reorder point</div>
                <div className="text-lg font-semibold tabular-nums">
                  {lookupRec.reorder_point}
                </div>
              </div>
              <div>
                <div className="text-muted-foreground">Status</div>
                <div className="pt-1">{statusBadge(lookupRec.status)}</div>
              </div>
            </div>
          )}

          {/* Set on-hand */}
          <div className="flex flex-wrap items-end gap-2 border-t pt-4">
            <div>
              <Label htmlFor="on-hand">Set on-hand</Label>
              <Input
                id="on-hand"
                type="number"
                min={0}
                value={onHandValue}
                onChange={(e) => setOnHandValue(e.target.value)}
                placeholder="0"
                className="w-28"
              />
            </div>
            <div>
              <Label htmlFor="reorder">Reorder point (optional)</Label>
              <Input
                id="reorder"
                type="number"
                min={0}
                value={reorderValue}
                onChange={(e) => setReorderValue(e.target.value)}
                placeholder="—"
                className="w-36"
              />
            </div>
            <Button
              disabled={
                (!loadedSku && !skuQuery.trim()) ||
                onHandValue === "" ||
                Number.isNaN(Number(onHandValue)) ||
                Number(onHandValue) < 0 ||
                setOnHandMut.isPending
              }
              onClick={() => setOnHandMut.mutate()}
            >
              {setOnHandMut.isPending && (
                <Loader2 className="mr-1 h-4 w-4 animate-spin" />
              )}
              Save
            </Button>
            {lookupRec && (
              <div className="ml-2 flex items-center gap-1">
                <span className="text-sm text-muted-foreground">Adjust:</span>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={adjustMut.isPending}
                  onClick={() =>
                    adjustMut.mutate({ sku: lookupRec.sku, delta: 1 })
                  }
                >
                  +1
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={adjustMut.isPending}
                  onClick={() =>
                    adjustMut.mutate({ sku: lookupRec.sku, delta: -1 })
                  }
                >
                  −1
                </Button>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Low-stock view */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <AlertTriangle className="h-4 w-4 text-amber-500" />
            Low-stock items
          </CardTitle>
        </CardHeader>
        <CardContent>
          {lowStockQuery.isLoading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading…
            </div>
          ) : (lowStockQuery.data?.items ?? []).length === 0 ? (
            <EmptyState
              icon={<Package className="h-10 w-10" />}
              title="No low-stock items"
              description="All tracked SKUs are above their reorder point."
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>SKU</TableHead>
                  <TableHead>On hand</TableHead>
                  <TableHead>Reserved</TableHead>
                  <TableHead>Available</TableHead>
                  <TableHead>Reorder</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Adjust</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(lowStockQuery.data?.items ?? []).map((rec) => (
                  <InventoryRow
                    key={`${rec.sku}#${rec.location_id}`}
                    rec={rec}
                    onAdjust={(sku, delta) => adjustMut.mutate({ sku, delta })}
                  />
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default InventoryAdmin;
