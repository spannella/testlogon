import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ImagePlus, Plus, Send, Trash2 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  listCreatives,
  deleteCreative,
  submitCreativeForReview,
} from "@/api/endpoints/ads";
import type { AdCreative } from "@/api/types";
import CreativeEditor from "./CreativeEditor";
import CreativePreview from "./CreativePreview";

const statusVariant: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  draft: "outline",
  pending_review: "secondary",
  approved: "default",
  rejected: "destructive",
  archived: "outline",
};

const formatLabel: Record<string, string> = {
  image: "Image",
  video: "Video",
  native_post: "Native Post",
};

export default function CreativeListPage() {
  const [params] = useSearchParams();
  const campaignId = params.get("campaign") ?? "";
  const queryClient = useQueryClient();
  const [editorOpen, setEditorOpen] = useState(false);
  const [previewCreative, setPreviewCreative] = useState<AdCreative | null>(null);

  const { data: creatives = [], isLoading } = useQuery({
    queryKey: ["ad-creatives", campaignId],
    queryFn: () => listCreatives(campaignId),
    enabled: !!campaignId,
    staleTime: 30_000,
  });

  const deleteMut = useMutation({
    mutationFn: (creativeId: string) => deleteCreative(campaignId, creativeId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ad-creatives", campaignId] });
    },
  });

  const submitMut = useMutation({
    mutationFn: (creativeId: string) => submitCreativeForReview(campaignId, creativeId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ad-creatives", campaignId] });
    },
  });

  if (!campaignId) {
    return (
      <div className="mx-auto max-w-4xl p-6">
        <p className="text-muted-foreground">No campaign selected.</p>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6 p-6">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div className="flex items-center gap-2">
            <ImagePlus className="h-6 w-6" />
            <CardTitle>Ad Creatives</CardTitle>
          </div>
          <Button onClick={() => setEditorOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            New Creative
          </Button>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-muted-foreground">Loading creatives...</p>
          ) : (creatives as AdCreative[]).length === 0 ? (
            <p className="text-muted-foreground">
              No creatives yet. Create one to get started.
            </p>
          ) : (
            <div className="space-y-4">
              {(creatives as AdCreative[]).map((cr) => (
                <Card key={cr.creative_id}>
                  <CardContent className="flex items-center justify-between py-4">
                    <div
                      className="flex-1 cursor-pointer"
                      onClick={() => setPreviewCreative(cr)}
                    >
                      <p className="font-semibold">{cr.title}</p>
                      <p className="text-sm text-muted-foreground">
                        {formatLabel[cr.format] ?? cr.format} &middot; Weight: {cr.rotation_weight}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={statusVariant[cr.status] ?? "outline"}>
                        {cr.status.replace(/_/g, " ")}
                      </Badge>
                      {cr.status === "draft" && (
                        <>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => submitMut.mutate(cr.creative_id)}
                          >
                            <Send className="mr-1 h-3 w-3" />
                            Submit
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => deleteMut.mutate(cr.creative_id)}
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create dialog */}
      <Dialog open={editorOpen} onOpenChange={setEditorOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Create New Creative</DialogTitle>
          </DialogHeader>
          <CreativeEditor
            campaignId={campaignId}
            onSaved={() => setEditorOpen(false)}
          />
        </DialogContent>
      </Dialog>

      {/* Preview dialog */}
      <Dialog open={!!previewCreative} onOpenChange={(open) => { if (!open) setPreviewCreative(null); }}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{previewCreative?.title}</DialogTitle>
          </DialogHeader>
          {previewCreative && <CreativePreview creative={previewCreative} />}
        </DialogContent>
      </Dialog>
    </div>
  );
}
