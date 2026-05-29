import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Shield, CheckCircle, XCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { listPendingCreatives, reviewCreative } from "@/api/endpoints/ads";
import type { AdCreative } from "@/api/types";
import CreativePreview from "./CreativePreview";

const formatLabel: Record<string, string> = {
  image: "Image Banner",
  video: "Video Ad",
  native_post: "Native Post",
};

export default function AdminCreativeReviewPage() {
  const queryClient = useQueryClient();
  const [reviewTarget, setReviewTarget] = useState<AdCreative | null>(null);
  const [reviewNotes, setReviewNotes] = useState("");

  const { data: pending = [], isLoading } = useQuery({
    queryKey: ["admin-creatives-pending"],
    queryFn: () => listPendingCreatives(),
    staleTime: 10_000,
  });

  const reviewMut = useMutation({
    mutationFn: ({ creativeId, decision, notes }: { creativeId: string; decision: string; notes: string }) =>
      reviewCreative(creativeId, { decision, notes }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin-creatives-pending"] });
      setReviewTarget(null);
      setReviewNotes("");
    },
  });

  return (
    <div data-testid="admin-creative-review" className="mx-auto max-w-4xl space-y-6 p-6">
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6" />
            <CardTitle>Creative Review Queue</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-muted-foreground">Loading pending creatives...</p>
          ) : (pending as AdCreative[]).length === 0 ? (
            <p className="text-muted-foreground">No creatives pending review.</p>
          ) : (
            <div className="space-y-4">
              {(pending as AdCreative[]).map((cr) => (
                <Card key={cr.creative_id} className="cursor-pointer hover:bg-accent/50 transition-colors"
                  onClick={() => setReviewTarget(cr)}
                >
                  <CardContent className="flex items-center justify-between py-4">
                    <div>
                      <p className="font-semibold">{cr.title}</p>
                      <p className="text-sm text-muted-foreground">
                        {formatLabel[cr.format] ?? cr.format} &middot; Campaign: {cr.campaign_id}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary">Pending Review</Badge>
                      {cr.image_url && (
                        <img src={cr.image_url} alt="" className="h-10 w-10 rounded object-cover" />
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={!!reviewTarget} onOpenChange={(open) => { if (!open) setReviewTarget(null); }}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Review Creative: {reviewTarget?.title}</DialogTitle>
          </DialogHeader>

          {reviewTarget && (
            <div className="space-y-4">
              <CreativePreview creative={reviewTarget} />

              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Format:</span>{" "}
                  {formatLabel[reviewTarget.format] ?? reviewTarget.format}
                </div>
                <div>
                  <span className="text-muted-foreground">Campaign:</span>{" "}
                  {reviewTarget.campaign_id}
                </div>
                {reviewTarget.width && reviewTarget.height && (
                  <div>
                    <span className="text-muted-foreground">Dimensions:</span>{" "}
                    {reviewTarget.width}x{reviewTarget.height}
                  </div>
                )}
                {reviewTarget.duration_seconds && (
                  <div>
                    <span className="text-muted-foreground">Duration:</span>{" "}
                    {reviewTarget.duration_seconds}s
                  </div>
                )}
                <div>
                  <span className="text-muted-foreground">Weight:</span>{" "}
                  {reviewTarget.rotation_weight}
                </div>
              </div>

              <div>
                <Label htmlFor="review-notes">Review Notes</Label>
                <Textarea
                  id="review-notes"
                  value={reviewNotes}
                  onChange={(e) => setReviewNotes(e.target.value)}
                  placeholder="Optional notes for the advertiser..."
                  maxLength={1000}
                />
              </div>
            </div>
          )}

          <DialogFooter>
            <Button
              variant="destructive"
              onClick={() =>
                reviewTarget &&
                reviewMut.mutate({
                  creativeId: reviewTarget.creative_id,
                  decision: "reject",
                  notes: reviewNotes,
                })
              }
              disabled={reviewMut.isPending}
            >
              <XCircle className="mr-2 h-4 w-4" />
              Reject
            </Button>
            <Button
              onClick={() =>
                reviewTarget &&
                reviewMut.mutate({
                  creativeId: reviewTarget.creative_id,
                  decision: "approve",
                  notes: reviewNotes,
                })
              }
              disabled={reviewMut.isPending}
            >
              <CheckCircle className="mr-2 h-4 w-4" />
              Approve
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
