import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArrowLeft, Ban } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  getAsset,
  type FixedAsset,
} from "@/api/endpoints/fixedAssets";
import { DepreciationScheduleView } from "./DepreciationScheduleView";
import { DisposalForm } from "./DisposalForm";
import { WorkOrdersPanel } from "./WorkOrdersPanel";
import { fmtCents, fmtTs, fmtTsTime, prettyStatus, statusVariant } from "./lib";

interface Props {
  assetId: string;
  onBack: () => void;
}

function StatRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between border-b py-2 last:border-0">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className="text-sm font-medium tabular-nums">{value}</span>
    </div>
  );
}

export function FixedAssetDetail({ assetId, onBack }: Props) {
  const qc = useQueryClient();
  const [disposeOpen, setDisposeOpen] = useState(false);

  const assetQuery = useQuery({
    queryKey: ["fixed-assets", "detail", assetId],
    queryFn: () => getAsset(assetId),
    retry: false,
  });

  const asset: FixedAsset | undefined = assetQuery.data;

  const refreshAll = () => {
    void qc.invalidateQueries({ queryKey: ["fixed-assets", "detail", assetId] });
    void qc.invalidateQueries({ queryKey: ["fixed-assets", "schedule", assetId] });
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title={asset?.name ?? "Asset"}
        description={asset ? `${prettyStatus(asset.asset_class)} · ${asset.asset_id}` : undefined}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={onBack}>
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Button>
            {asset && asset.status !== "disposed" && (
              <Button
                variant="destructive"
                size="sm"
                onClick={() => setDisposeOpen(true)}
              >
                <Ban className="mr-2 h-4 w-4" />
                Dispose
              </Button>
            )}
          </div>
        }
      />

      {assetQuery.isLoading ? (
        <p className="py-8 text-center text-sm text-muted-foreground">Loading asset…</p>
      ) : assetQuery.isError || !asset ? (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            Unable to load this asset.
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-3">
            <Card className="md:col-span-1">
              <CardHeader>
                <CardTitle className="flex items-center justify-between gap-2 text-base">
                  Overview
                  <Badge variant={statusVariant(asset.status)}>
                    {prettyStatus(asset.status)}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-0">
                <StatRow label="Acquisition cost" value={fmtCents(asset.acquisition_cost_cents)} />
                <StatRow label="Salvage value" value={fmtCents(asset.salvage_value_cents)} />
                <StatRow
                  label="Accumulated depreciation"
                  value={fmtCents(asset.accumulated_depreciation_cents)}
                />
                <StatRow
                  label="Net book value"
                  value={
                    <span className="text-base font-semibold">
                      {fmtCents(asset.net_book_value_cents)}
                    </span>
                  }
                />
                <StatRow label="Useful life" value={`${asset.useful_life_months} months`} />
                <StatRow label="Method" value={prettyStatus(asset.depreciation_method)} />
                <StatRow label="Acquired" value={fmtTs(asset.acquired_at)} />
                <StatRow label="Owner" value={asset.owner_sub} />
                <StatRow label="Created" value={fmtTsTime(asset.created_at)} />
              </CardContent>
            </Card>

            <Card className="md:col-span-2">
              <CardHeader>
                <CardTitle className="text-base">Schedule & maintenance</CardTitle>
                <CardDescription>
                  Generate the depreciation schedule, post periods to the GL, and manage work orders.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="schedule">
                  <TabsList>
                    <TabsTrigger value="schedule">Depreciation</TabsTrigger>
                    <TabsTrigger value="work-orders">Work orders</TabsTrigger>
                  </TabsList>
                  <TabsContent value="schedule" className="pt-4">
                    <DepreciationScheduleView
                      asset={asset}
                      onChanged={refreshAll}
                    />
                  </TabsContent>
                  <TabsContent value="work-orders" className="pt-4">
                    <WorkOrdersPanel asset={asset} />
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </div>

          <DisposalForm
            asset={asset}
            open={disposeOpen}
            onOpenChange={setDisposeOpen}
            onDisposed={() => {
              toast.success("Asset disposed");
              refreshAll();
            }}
          />
        </>
      )}
    </div>
  );
}
