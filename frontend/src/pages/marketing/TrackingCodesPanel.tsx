import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Link2, Plus, Search } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

import {
  createTrackingCode,
  getTrackingCode,
  listCampaigns,
  type TrackingCode,
} from "@/api/endpoints/marketing";
import { EmptyState, NotEnabledCard, errMsg, fmtTs, isNotEnabledError } from "./shared";

export function TrackingCodesPanel() {
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [slug, setSlug] = useState("");
  const [campaignId, setCampaignId] = useState("");
  const [lookupSlug, setLookupSlug] = useState("");
  const [lookupResult, setLookupResult] = useState<TrackingCode | null>(null);

  // Used both to populate the create form's campaign list and to detect 404 disabled.
  const campaignsQ = useQuery({
    queryKey: ["mkt", "campaigns"],
    queryFn: () => listCampaigns({ limit: 100 }),
    retry: false,
  });

  const createMut = useMutation({
    mutationFn: () => createTrackingCode({ code_slug: slug.trim(), campaign_id: campaignId.trim() }),
    onSuccess: (tc) => {
      toast.success("Tracking code created");
      setCreateOpen(false);
      setSlug("");
      setCampaignId("");
      setLookupSlug(tc.code_slug);
      setLookupResult(tc);
      void qc.invalidateQueries({ queryKey: ["mkt", "tracking", tc.code_slug] });
    },
    onError: (e) => toast.error(errMsg(e, "Unable to create tracking code")),
  });

  const lookupMut = useMutation({
    mutationFn: (s: string) => getTrackingCode(s),
    onSuccess: (tc) => setLookupResult(tc),
    onError: (e) => {
      setLookupResult(null);
      toast.error(errMsg(e, "Tracking code not found"));
    },
  });

  if (isNotEnabledError(campaignsQ.error)) {
    return <NotEnabledCard what="Tracking codes" />;
  }

  const campaigns = campaignsQ.data?.campaigns ?? [];

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Link2 className="h-4 w-4" /> Tracking codes
            </CardTitle>
            <CardDescription>Attribute visits and orders to a campaign.</CardDescription>
          </div>
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="mr-1 h-3.5 w-3.5" /> New
          </Button>
        </CardHeader>
        <CardContent className="space-y-3">
          <Label className="text-xs uppercase text-muted-foreground">Look up a code</Label>
          <div className="flex gap-2">
            <Input
              placeholder="code slug"
              value={lookupSlug}
              onChange={(e) => setLookupSlug(e.target.value)}
            />
            <Button
              variant="outline"
              disabled={!lookupSlug.trim() || lookupMut.isPending}
              onClick={() => lookupMut.mutate(lookupSlug.trim())}
            >
              <Search className="mr-1 h-3.5 w-3.5" /> Lookup
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Result</CardTitle>
          <CardDescription>Visit & order counters.</CardDescription>
        </CardHeader>
        <CardContent>
          {!lookupResult ? (
            <EmptyState title="No tracking code loaded" hint="Create or look one up." />
          ) : (
            <dl className="grid grid-cols-2 gap-y-2 text-sm">
              <dt className="text-muted-foreground">Slug</dt>
              <dd className="font-mono">{lookupResult.code_slug}</dd>
              <dt className="text-muted-foreground">Campaign</dt>
              <dd className="font-mono text-xs">{lookupResult.campaign_id}</dd>
              <dt className="text-muted-foreground">Visits</dt>
              <dd>
                <Badge variant="secondary">{lookupResult.visit_count}</Badge>
              </dd>
              <dt className="text-muted-foreground">Orders</dt>
              <dd>
                <Badge variant="secondary">{lookupResult.order_count}</Badge>
              </dd>
              <dt className="text-muted-foreground">Created</dt>
              <dd>{fmtTs(lookupResult.created_at)}</dd>
              <dt className="text-muted-foreground">Public link</dt>
              <dd className="break-all font-mono text-xs">
                /ui/marketing/t/{lookupResult.code_slug}
              </dd>
            </dl>
          )}
        </CardContent>
      </Card>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New tracking code</DialogTitle>
            <DialogDescription>
              Slug: 3–50 chars (letters, digits, _ and -).
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label htmlFor="tc-slug">Code slug</Label>
              <Input
                id="tc-slug"
                value={slug}
                onChange={(e) => setSlug(e.target.value)}
                placeholder="spring2026"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="tc-campaign">Campaign id</Label>
              <Input
                id="tc-campaign"
                list="tc-campaign-options"
                value={campaignId}
                onChange={(e) => setCampaignId(e.target.value)}
                placeholder="campaign id"
              />
              <datalist id="tc-campaign-options">
                {campaigns.map((c) => (
                  <option key={c.campaign_id} value={c.campaign_id}>
                    {c.name}
                  </option>
                ))}
              </datalist>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              disabled={!slug.trim() || !campaignId.trim() || createMut.isPending}
              onClick={() => createMut.mutate()}
            >
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
