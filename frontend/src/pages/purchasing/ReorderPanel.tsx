import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { AlertTriangle } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";

import {
  getReorderSuggestions,
  createPoFromSuggestion,
  formatCents,
  type ReorderSuggestion,
} from "@/api/endpoints/purchasing";
import { ApiError } from "@/api/client";

function isFeatureDisabled(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

export function ReorderPanel() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [selected, setSelected] = useState<Record<string, Set<string>>>({});

  const query = useQuery({
    queryKey: ["purchasing", "reorder"],
    queryFn: () => getReorderSuggestions(),
    retry: (count, err) => !isFeatureDisabled(err) && count < 2,
  });

  const createMut = useMutation({
    mutationFn: ({ supplierId, skus }: { supplierId: string; skus: string[] }) =>
      createPoFromSuggestion(supplierId, skus),
    onSuccess: (po) => {
      toast.success("Purchase order created from suggestions");
      void qc.invalidateQueries({ queryKey: ["purchasing", "pos"] });
      navigate(`/purchasing/purchase-orders/${po.po_id}`);
    },
    onError: (err: unknown) =>
      toast.error(err instanceof Error ? err.message : "Unable to create PO"),
  });

  const suggestions: ReorderSuggestion[] = query.data?.suggestions ?? [];

  // Group suggestions by supplier (only those with a supplier are actionable)
  const bySupplier = useMemo(() => {
    const map = new Map<string, { name: string; items: ReorderSuggestion[] }>();
    for (const s of suggestions) {
      if (!s.supplier_id) continue;
      const cur = map.get(s.supplier_id) ?? { name: s.supplier_name ?? s.supplier_id, items: [] };
      cur.items.push(s);
      map.set(s.supplier_id, cur);
    }
    return map;
  }, [suggestions]);

  const orphans = suggestions.filter((s) => !s.supplier_id);

  const toggle = (supplierId: string, sku: string) =>
    setSelected((prev) => {
      const set = new Set(prev[supplierId] ?? []);
      if (set.has(sku)) set.delete(sku);
      else set.add(sku);
      return { ...prev, [supplierId]: set };
    });

  if (isFeatureDisabled(query.error)) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-muted-foreground">
          Purchasing is not enabled.
        </CardContent>
      </Card>
    );
  }

  if (query.isLoading) {
    return (
      <Card>
        <CardContent className="space-y-2 p-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </CardContent>
      </Card>
    );
  }

  if (suggestions.length === 0) {
    return (
      <Card>
        <CardContent className="py-12 text-center text-sm text-muted-foreground">
          No reorder suggestions — all stock levels are healthy.
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {Array.from(bySupplier.entries()).map(([supplierId, group]) => {
        const sel = selected[supplierId] ?? new Set<string>();
        return (
          <Card key={supplierId}>
            <CardContent className="p-0">
              <div className="flex items-center justify-between border-b px-4 py-3">
                <div className="font-medium">{group.name}</div>
                <Button
                  size="sm"
                  disabled={sel.size === 0 || createMut.isPending}
                  onClick={() =>
                    createMut.mutate({ supplierId, skus: Array.from(sel) })
                  }
                >
                  Create PO ({sel.size})
                </Button>
              </div>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10" />
                    <TableHead>SKU</TableHead>
                    <TableHead className="text-right">Available</TableHead>
                    <TableHead className="text-right">Reorder pt</TableHead>
                    <TableHead className="text-right">Suggested qty</TableHead>
                    <TableHead className="text-right">Unit cost</TableHead>
                    <TableHead className="text-right">Lead time</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {group.items.map((it) => (
                    <TableRow key={it.sku}>
                      <TableCell>
                        <Checkbox
                          checked={sel.has(it.sku)}
                          onCheckedChange={() => toggle(supplierId, it.sku)}
                        />
                      </TableCell>
                      <TableCell className="font-mono text-xs">{it.sku}</TableCell>
                      <TableCell className="text-right">{it.available}</TableCell>
                      <TableCell className="text-right">{it.reorder_point}</TableCell>
                      <TableCell className="text-right font-medium">{it.suggested_qty}</TableCell>
                      <TableCell className="text-right">
                        {it.unit_cost_cents != null
                          ? formatCents(it.unit_cost_cents)
                          : "—"}
                      </TableCell>
                      <TableCell className="text-right">
                        {it.lead_time_days != null ? `${it.lead_time_days}d` : "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        );
      })}

      {orphans.length > 0 && (
        <Card>
          <CardContent className="p-4">
            <div className="mb-2 flex items-center gap-2 text-sm font-medium text-warning">
              <AlertTriangle className="h-4 w-4" />
              SKUs needing reorder with no preferred supplier
            </div>
            <div className="flex flex-wrap gap-2">
              {orphans.map((o) => (
                <Badge key={o.sku} variant="outline" className="font-mono">
                  {o.sku} (avail {o.available})
                </Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
