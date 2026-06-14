import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ArrowRightLeft,
  ClipboardList,
  Truck,
  Search,
  PackageCheck,
} from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
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
  advanceTransfer,
  cancelShipment,
  cancelTransfer,
  completeTransfer,
  confirmPick,
  getPicklist,
  getShipment,
  listTransfers,
  packPicklist,
  shipShipment,
  type Picklist,
  type Shipment,
  type ShipmentIn,
  type Transfer,
  type TransferStatus,
} from "@/api/endpoints/facility";
import {
  FeatureDisabledCard,
  formatTs,
  isFeatureDisabled,
  retryUnlessDisabled,
  statusBadgeClass,
} from "./facilityUtils";

const TRANSFER_STATUSES: TransferStatus[] = [
  "requested",
  "in_transit",
  "completed",
  "cancelled",
];

export default function FulfillmentPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Fulfillment"
        description="Inventory transfers, pick & pack, and outbound shipments (OFBiz FAC-006..010)"
      />
      <Tabs defaultValue="transfers">
        <TabsList>
          <TabsTrigger value="transfers">
            <ArrowRightLeft className="mr-1 h-4 w-4" /> Transfers
          </TabsTrigger>
          <TabsTrigger value="pickpack">
            <ClipboardList className="mr-1 h-4 w-4" /> Pick &amp; Pack
          </TabsTrigger>
          <TabsTrigger value="shipments">
            <Truck className="mr-1 h-4 w-4" /> Shipments
          </TabsTrigger>
        </TabsList>
        <TabsContent value="transfers" className="mt-4">
          <TransfersTab />
        </TabsContent>
        <TabsContent value="pickpack" className="mt-4">
          <PickPackTab />
        </TabsContent>
        <TabsContent value="shipments" className="mt-4">
          <ShipmentsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// Transfers tab
// ═════════════════════════════════════════════════════════════════════════════

function TransfersTab() {
  const qc = useQueryClient();
  const [status, setStatus] = useState<TransferStatus>("requested");

  const query = useQuery({
    queryKey: ["fulfillment", "transfers", status],
    queryFn: () => listTransfers({ status, limit: 100 }),
    retry: retryUnlessDisabled,
  });

  const invalidate = () =>
    void qc.invalidateQueries({ queryKey: ["fulfillment", "transfers"] });

  const advanceMut = useMutation({
    mutationFn: (id: string) => advanceTransfer(id),
    onSuccess: () => {
      toast.success("Transfer in transit");
      invalidate();
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed"),
  });
  const completeMut = useMutation({
    mutationFn: (id: string) => completeTransfer(id),
    onSuccess: () => {
      toast.success("Transfer completed");
      invalidate();
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed"),
  });
  const cancelMut = useMutation({
    mutationFn: (id: string) => cancelTransfer(id),
    onSuccess: () => {
      toast.success("Transfer cancelled");
      invalidate();
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed"),
  });

  if (isFeatureDisabled(query.error)) return <FeatureDisabledCard />;

  const transfers = query.data?.transfers ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Inventory transfers</CardTitle>
        <CardDescription>Move stock between facilities and locations.</CardDescription>
        <div className="flex flex-wrap gap-1 pt-2">
          {TRANSFER_STATUSES.map((s) => (
            <Button
              key={s}
              size="sm"
              variant={status === s ? "default" : "outline"}
              onClick={() => setStatus(s)}
              className="capitalize"
            >
              {s.replace(/_/g, " ")}
            </Button>
          ))}
        </div>
      </CardHeader>
      <CardContent>
        {query.isLoading ? (
          <Skeleton className="h-24 w-full" />
        ) : transfers.length === 0 ? (
          <p className="py-10 text-center text-sm text-muted-foreground">
            No {status.replace(/_/g, " ")} transfers.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Transfer</TableHead>
                <TableHead>From → To</TableHead>
                <TableHead>Lines</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {transfers.map((t: Transfer) => (
                <TableRow key={t.transfer_id}>
                  <TableCell className="font-mono text-xs">{t.transfer_id}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {t.from_facility_id} → {t.to_facility_id}
                  </TableCell>
                  <TableCell>{t.lines.length}</TableCell>
                  <TableCell>
                    <Badge variant="secondary" className={statusBadgeClass(t.status)}>
                      {t.status.replace(/_/g, " ")}
                    </Badge>
                  </TableCell>
                  <TableCell className="space-x-1 text-right">
                    {t.status === "requested" && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => advanceMut.mutate(t.transfer_id)}
                        disabled={advanceMut.isPending}
                      >
                        Ship
                      </Button>
                    )}
                    {t.status === "in_transit" && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => completeMut.mutate(t.transfer_id)}
                        disabled={completeMut.isPending}
                      >
                        Complete
                      </Button>
                    )}
                    {(t.status === "requested" || t.status === "in_transit") && (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => cancelMut.mutate(t.transfer_id)}
                        disabled={cancelMut.isPending}
                      >
                        Cancel
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
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// Pick & Pack tab — lookup a picklist, confirm picks, pack
// ═════════════════════════════════════════════════════════════════════════════

function PickPackTab() {
  const [lookupId, setLookupId] = useState("");
  const [activeId, setActiveId] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["fulfillment", "picklist", activeId],
    queryFn: () => getPicklist(activeId!),
    enabled: !!activeId,
    retry: retryUnlessDisabled,
  });

  if (isFeatureDisabled(query.error)) return <FeatureDisabledCard />;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Look up picklist</CardTitle>
          <CardDescription>
            Open a picklist by ID to confirm picks and pack the order.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (lookupId.trim()) setActiveId(lookupId.trim());
            }}
          >
            <div className="flex-1 space-y-1.5">
              <Label htmlFor="pl-id">Picklist ID</Label>
              <Input
                id="pl-id"
                value={lookupId}
                onChange={(e) => setLookupId(e.target.value)}
                placeholder="PL_..."
              />
            </div>
            <Button type="submit" disabled={!lookupId.trim()}>
              <Search className="mr-1 h-4 w-4" /> Open
            </Button>
          </form>
        </CardContent>
      </Card>

      {activeId && (
        <>
          {query.isLoading ? (
            <Skeleton className="h-40 w-full" />
          ) : query.isError ? (
            <Card>
              <CardContent className="py-8 text-center text-sm text-muted-foreground">
                Picklist not found.
              </CardContent>
            </Card>
          ) : query.data ? (
            <PicklistDetail picklist={query.data} onChanged={() => void query.refetch()} />
          ) : null}
        </>
      )}
    </div>
  );
}

function PicklistDetail({
  picklist,
  onChanged,
}: {
  picklist: Picklist;
  onChanged: () => void;
}) {
  const [packOpen, setPackOpen] = useState(false);
  const [pickQty, setPickQty] = useState<Record<string, string>>({});

  const confirmMut = useMutation({
    mutationFn: ({ lineNo, qty }: { lineNo: number; qty: number }) =>
      confirmPick(picklist.picklist_id, lineNo, qty),
    onSuccess: () => {
      toast.success("Pick confirmed");
      onChanged();
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed"),
  });

  const lineNoOf = (lineId: string): number => {
    const m = lineId.match(/(\d+)\s*$/);
    return m ? Number(m[1]) : 0;
  };

  const allPicked = picklist.lines.every((l) => l.status === "picked");

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="font-mono text-base">{picklist.picklist_id}</CardTitle>
            <CardDescription>
              Order {picklist.order_id} · created {formatTs(picklist.created_at)}
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="secondary" className={statusBadgeClass(picklist.status)}>
              {picklist.status}
            </Badge>
            {(picklist.status === "picked" || allPicked) &&
              picklist.status !== "packed" &&
              picklist.status !== "cancelled" && (
                <Button size="sm" onClick={() => setPackOpen(true)}>
                  <PackageCheck className="mr-1 h-4 w-4" /> Pack
                </Button>
              )}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>SKU</TableHead>
              <TableHead>Requested</TableHead>
              <TableHead>Picked</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Confirm</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {picklist.lines.map((l) => {
              const lineNo = lineNoOf(l.line_id);
              return (
                <TableRow key={l.line_id}>
                  <TableCell className="font-medium">{l.sku}</TableCell>
                  <TableCell>{l.requested_quantity}</TableCell>
                  <TableCell>{l.picked_quantity}</TableCell>
                  <TableCell>
                    <Badge variant="secondary" className={statusBadgeClass(l.status)}>
                      {l.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    {l.status === "pending" ? (
                      <div className="flex items-center justify-end gap-1">
                        <Input
                          type="number"
                          min={0}
                          className="h-8 w-20"
                          value={pickQty[l.line_id] ?? String(l.requested_quantity)}
                          onChange={(e) =>
                            setPickQty((p) => ({ ...p, [l.line_id]: e.target.value }))
                          }
                        />
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={confirmMut.isPending}
                          onClick={() =>
                            confirmMut.mutate({
                              lineNo,
                              qty: Number(
                                pickQty[l.line_id] ?? l.requested_quantity,
                              ),
                            })
                          }
                        >
                          Confirm
                        </Button>
                      </div>
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </CardContent>

      <PackDialog
        picklist={picklist}
        open={packOpen}
        onOpenChange={setPackOpen}
        onPacked={onChanged}
      />
    </Card>
  );
}

function PackDialog({
  picklist,
  open,
  onOpenChange,
  onPacked,
}: {
  picklist: Picklist;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onPacked: () => void;
}) {
  const [weight, setWeight] = useState("");

  const mut = useMutation({
    mutationFn: () => {
      // Single package containing every picked line.
      const body: ShipmentIn = {
        picklist_id: picklist.picklist_id,
        carrier: "PENDING",
        tracking_number: "PENDING",
        packages: [
          {
            weight_grams: weight ? Number(weight) : null,
            contents: picklist.lines
              .filter((l) => l.picked_quantity > 0)
              .map((l) => ({
                order_line_id: l.order_line_id,
                sku: l.sku,
                quantity: l.picked_quantity,
              })),
          },
        ],
      };
      return packPicklist(picklist.picklist_id, body);
    },
    onSuccess: () => {
      toast.success("Packed — shipment created in draft");
      setWeight("");
      onOpenChange(false);
      onPacked();
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Pack failed"),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Pack picklist</DialogTitle>
          <DialogDescription>
            Creates a single package with all picked lines and a draft shipment.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-2 py-2">
          <Label htmlFor="pack-weight">Package weight (grams, optional)</Label>
          <Input
            id="pack-weight"
            type="number"
            min={0}
            value={weight}
            onChange={(e) => setWeight(e.target.value)}
            placeholder="500"
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={() => mut.mutate()} disabled={mut.isPending}>
            Pack
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// Shipments tab — lookup by ID, ship / cancel
// ═════════════════════════════════════════════════════════════════════════════

function ShipmentsTab() {
  const [lookupId, setLookupId] = useState("");
  const [activeId, setActiveId] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["fulfillment", "shipment", activeId],
    queryFn: () => getShipment(activeId!),
    enabled: !!activeId,
    retry: retryUnlessDisabled,
  });

  if (isFeatureDisabled(query.error)) return <FeatureDisabledCard />;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Look up shipment</CardTitle>
          <CardDescription>Open a shipment by ID to dispatch or cancel it.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (lookupId.trim()) setActiveId(lookupId.trim());
            }}
          >
            <div className="flex-1 space-y-1.5">
              <Label htmlFor="sh-id">Shipment ID</Label>
              <Input
                id="sh-id"
                value={lookupId}
                onChange={(e) => setLookupId(e.target.value)}
                placeholder="SH_..."
              />
            </div>
            <Button type="submit" disabled={!lookupId.trim()}>
              <Search className="mr-1 h-4 w-4" /> Open
            </Button>
          </form>
        </CardContent>
      </Card>

      {activeId && (
        <>
          {query.isLoading ? (
            <Skeleton className="h-40 w-full" />
          ) : query.isError ? (
            <Card>
              <CardContent className="py-8 text-center text-sm text-muted-foreground">
                Shipment not found.
              </CardContent>
            </Card>
          ) : query.data ? (
            <ShipmentDetail shipment={query.data} onChanged={() => void query.refetch()} />
          ) : null}
        </>
      )}
    </div>
  );
}

function ShipmentDetail({
  shipment,
  onChanged,
}: {
  shipment: Shipment;
  onChanged: () => void;
}) {
  const [carrier, setCarrier] = useState("");
  const [tracking, setTracking] = useState("");
  const [service, setService] = useState("");

  const shipMut = useMutation({
    mutationFn: () => {
      const body: ShipmentIn = {
        picklist_id: shipment.picklist_id,
        carrier: carrier.trim(),
        tracking_number: tracking.trim(),
        service_level: service.trim() || null,
        packages: shipment.packages.map((p) => ({
          weight_grams: p.weight_grams,
          length_mm: p.length_mm,
          width_mm: p.width_mm,
          height_mm: p.height_mm,
          contents: p.contents,
          notes: p.notes,
        })),
      };
      return shipShipment(shipment.shipment_id, body);
    },
    onSuccess: () => {
      toast.success("Shipment dispatched");
      onChanged();
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Ship failed"),
  });

  const cancelMut = useMutation({
    mutationFn: () => cancelShipment(shipment.shipment_id, "cancelled via UI"),
    onSuccess: () => {
      toast.success("Shipment cancelled");
      onChanged();
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Cancel failed"),
  });

  const canShip = shipment.status === "draft" || shipment.status === "packed";

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div>
            <CardTitle className="font-mono text-base">{shipment.shipment_id}</CardTitle>
            <CardDescription>
              Order {shipment.order_id} · picklist {shipment.picklist_id}
            </CardDescription>
          </div>
          <Badge variant="secondary" className={statusBadgeClass(shipment.status)}>
            {shipment.status}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-5">
        <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
          <dt className="text-muted-foreground">Carrier</dt>
          <dd>{shipment.carrier || "—"}</dd>
          <dt className="text-muted-foreground">Tracking</dt>
          <dd className="font-mono text-xs">{shipment.tracking_number || "—"}</dd>
          <dt className="text-muted-foreground">Service level</dt>
          <dd>{shipment.service_level || "—"}</dd>
          <dt className="text-muted-foreground">Shipped</dt>
          <dd>{formatTs(shipment.shipped_at)}</dd>
          <dt className="text-muted-foreground">Delivered</dt>
          <dd>{formatTs(shipment.delivered_at)}</dd>
        </dl>

        <div>
          <h3 className="mb-2 text-sm font-medium">
            Packages ({shipment.packages.length})
          </h3>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Package</TableHead>
                <TableHead>Weight (g)</TableHead>
                <TableHead>Items</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {shipment.packages.map((p) => (
                <TableRow key={p.package_id}>
                  <TableCell className="font-mono text-xs">{p.package_id}</TableCell>
                  <TableCell>{p.weight_grams || "—"}</TableCell>
                  <TableCell>
                    {p.contents.reduce((s, c) => s + c.quantity, 0)} units
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>

        {canShip && (
          <div className="space-y-3 border-t pt-4">
            <h3 className="text-sm font-medium">Dispatch</h3>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="space-y-1.5">
                <Label htmlFor="sh-carrier">Carrier</Label>
                <Input
                  id="sh-carrier"
                  value={carrier}
                  onChange={(e) => setCarrier(e.target.value)}
                  placeholder="UPS"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="sh-track">Tracking #</Label>
                <Input
                  id="sh-track"
                  value={tracking}
                  onChange={(e) => setTracking(e.target.value)}
                  placeholder="1Z..."
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="sh-service">Service level</Label>
                <Input
                  id="sh-service"
                  value={service}
                  onChange={(e) => setService(e.target.value)}
                  placeholder="Ground"
                />
              </div>
            </div>
            <div className="flex gap-2">
              <Button
                onClick={() => shipMut.mutate()}
                disabled={!carrier.trim() || !tracking.trim() || shipMut.isPending}
              >
                <Truck className="mr-1 h-4 w-4" /> Ship
              </Button>
              <Button
                variant="outline"
                onClick={() => cancelMut.mutate()}
                disabled={cancelMut.isPending}
              >
                Cancel shipment
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
