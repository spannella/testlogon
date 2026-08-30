import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Megaphone, Plus, Pause, Play, Send, Archive, Sparkles } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  listCampaigns,
  createCampaign,
  updateCampaign,
  submitCampaignForReview,
} from "@/api/endpoints/ads";
import type { Campaign } from "@/api/types";
import CampaignEditor from "./CampaignEditor";
import PromoteCampaignDialog from "./PromoteCampaignDialog";

const statusVariant: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  draft: "outline",
  pending_review: "secondary",
  active: "default",
  paused: "secondary",
  completed: "outline",
  rejected: "destructive",
  archived: "outline",
};

export default function CampaignList() {
  const [params] = useSearchParams();
  const accountId = params.get("account") ?? "";
  const queryClient = useQueryClient();
  const [editorOpen, setEditorOpen] = useState(false);
  const [promoteOpen, setPromoteOpen] = useState(false);

  const { data: campaigns = [], isLoading } = useQuery({
    queryKey: ["ad-campaigns", accountId],
    queryFn: () => listCampaigns(accountId),
    enabled: !!accountId,
  });

  const createMut = useMutation({
    mutationFn: (data: {
      name: string;
      objective: string;
      budget_cents: number;
      budget_type: string;
    }) => createCampaign(accountId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ad-campaigns", accountId] });
      setEditorOpen(false);
    },
  });

  const updateStatusMut = useMutation({
    mutationFn: ({ campaignId, status }: { campaignId: string; status: string }) =>
      updateCampaign(accountId, campaignId, { status } as Partial<Campaign>),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ad-campaigns", accountId] });
    },
  });

  const submitMut = useMutation({
    mutationFn: (campaignId: string) =>
      submitCampaignForReview(accountId, campaignId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ad-campaigns", accountId] });
    },
  });

  if (!accountId) {
    return (
      <div className="mx-auto max-w-4xl p-6">
        <p className="text-muted-foreground">No account selected.</p>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-6">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div className="flex items-center gap-2">
            <Megaphone className="h-6 w-6" />
            <CardTitle>Campaigns</CardTitle>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => setPromoteOpen(true)}>
              <Sparkles className="mr-2 h-4 w-4" />
              Promote
            </Button>
            <Button onClick={() => setEditorOpen(true)}>
              <Plus className="mr-2 h-4 w-4" />
              Create Campaign
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-muted-foreground">Loading campaigns...</p>
          ) : (campaigns as Campaign[]).length === 0 ? (
            <p className="text-muted-foreground">
              No campaigns yet. Create one to get started.
            </p>
          ) : (
            <div className="space-y-4">
              {(campaigns as Campaign[]).map((camp) => (
                <Card key={camp.campaign_id}>
                  <CardContent className="flex items-center justify-between py-4">
                    <div>
                      <p className="font-semibold">{camp.name}</p>
                      <p className="text-sm text-muted-foreground">
                        {camp.objective} &middot; ${(camp.budget_cents / 100).toFixed(2)} {camp.budget_type}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        Spent: ${(camp.lifetime_spent_cents / 100).toFixed(2)}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={statusVariant[camp.status] ?? "outline"}>
                        {camp.status.replace("_", " ")}
                      </Badge>
                      {camp.status === "draft" && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => submitMut.mutate(camp.campaign_id)}
                        >
                          <Send className="mr-1 h-3 w-3" />
                          Submit
                        </Button>
                      )}
                      {camp.status === "active" && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            updateStatusMut.mutate({
                              campaignId: camp.campaign_id,
                              status: "paused",
                            })
                          }
                        >
                          <Pause className="mr-1 h-3 w-3" />
                          Pause
                        </Button>
                      )}
                      {camp.status === "paused" && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            updateStatusMut.mutate({
                              campaignId: camp.campaign_id,
                              status: "active",
                            })
                          }
                        >
                          <Play className="mr-1 h-3 w-3" />
                          Resume
                        </Button>
                      )}
                      {["draft", "active", "paused", "completed"].includes(camp.status) && (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() =>
                            updateStatusMut.mutate({
                              campaignId: camp.campaign_id,
                              status: "archived",
                            })
                          }
                        >
                          <Archive className="h-3 w-3" />
                        </Button>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <CampaignEditor
        open={editorOpen}
        onOpenChange={setEditorOpen}
        onSubmit={(data) => createMut.mutate(data)}
        isPending={createMut.isPending}
      />

      <PromoteCampaignDialog
        open={promoteOpen}
        onOpenChange={setPromoteOpen}
        accountId={accountId}
        onCreated={() =>
          queryClient.invalidateQueries({ queryKey: ["ad-campaigns", accountId] })
        }
      />
    </div>
  );
}
