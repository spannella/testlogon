import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  getOpenLicensingConfig,
  enableOpenLicensing,
  disableOpenLicensing,
  updateOpenLicensingTerms,
} from "@/api/endpoints/syndicateOpenLicensing";
import type { SyndicateOpenLicensingTerms } from "@/api/types";
import SyndicateOpenLicensingContentList from "./SyndicateOpenLicensingContentList";
import SyndicateOpenLicensingRegisterDialog from "./SyndicateOpenLicensingRegisterDialog";

const DEFAULT_TERMS: SyndicateOpenLicensingTerms = {
  profit_share_pct: 0,
  fixed_cost_cents: 0,
  revenue_share_pct: 0,
  currency: "usd",
};

export default function SyndicateOpenLicensingTab({
  syndicateId,
  isAdmin,
  currentUserId,
}: {
  syndicateId: string;
  isAdmin: boolean;
  currentUserId: string;
}) {
  const qc = useQueryClient();
  const [terms, setTerms] = useState<SyndicateOpenLicensingTerms>(DEFAULT_TERMS);

  const { data: config } = useQuery({
    queryKey: ["open-licensing-config", syndicateId],
    queryFn: () => getOpenLicensingConfig(syndicateId),
  });

  useEffect(() => {
    if (config?.open_licensing_terms) {
      setTerms(config.open_licensing_terms);
    }
  }, [config]);

  const enabled = !!config?.open_licensing_enabled;

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["open-licensing-config", syndicateId] });
    qc.invalidateQueries({ queryKey: ["open-licensing-content", syndicateId] });
  };

  const enableMut = useMutation({
    mutationFn: () => enableOpenLicensing(syndicateId, terms),
    onSuccess: () => {
      toast.success("Open licensing enabled");
      invalidate();
    },
    onError: () => toast.error("Failed to enable open licensing"),
  });

  const disableMut = useMutation({
    mutationFn: () => disableOpenLicensing(syndicateId),
    onSuccess: () => {
      toast.success("Open licensing disabled");
      invalidate();
    },
    onError: () => toast.error("Failed to disable open licensing"),
  });

  const termsMut = useMutation({
    mutationFn: () => updateOpenLicensingTerms(syndicateId, terms),
    onSuccess: () => {
      toast.success("Terms updated");
      invalidate();
    },
    onError: () => toast.error("Failed to update terms"),
  });

  const numField = (key: keyof SyndicateOpenLicensingTerms, label: string) => (
    <div className="space-y-1">
      <Label htmlFor={`ol-${key}`}>{label}</Label>
      <Input
        id={`ol-${key}`}
        type="number"
        min={0}
        value={String(terms[key] ?? 0)}
        disabled={!isAdmin}
        onChange={(e) =>
          setTerms((t) => ({ ...t, [key]: Number(e.target.value) || 0 }))
        }
      />
    </div>
  );

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            Open Licensing
            {enabled ? (
              <Badge data-testid="ol-status-enabled">Active</Badge>
            ) : (
              <Badge variant="outline" data-testid="ol-status-disabled">
                Disabled
              </Badge>
            )}
          </CardTitle>
          {isAdmin && (
            <Switch
              checked={enabled}
              data-testid="ol-toggle"
              onCheckedChange={(v) => (v ? enableMut.mutate() : disableMut.mutate())}
            />
          )}
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">
            When enabled, members' registered content is automatically licensed to
            every other member using the terms below. Existing auto-licenses remain
            active even after open licensing is disabled or a member leaves.
          </p>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
            {numField("profit_share_pct", "Profit Share %")}
            {numField("revenue_share_pct", "Revenue Share %")}
            {numField("fixed_cost_cents", "Fixed Cost (cents)")}
          </div>
          {isAdmin && enabled && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => termsMut.mutate()}
              disabled={termsMut.isPending}
            >
              Save Terms
            </Button>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Syndicate Content</CardTitle>
          {enabled && <SyndicateOpenLicensingRegisterDialog syndicateId={syndicateId} />}
        </CardHeader>
        <CardContent>
          <SyndicateOpenLicensingContentList
            syndicateId={syndicateId}
            currentUserId={currentUserId}
          />
        </CardContent>
      </Card>
    </div>
  );
}
