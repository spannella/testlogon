import { useParams } from "react-router-dom";
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getUIReview, createIssueTicket } from "@/api/endpoints/stylistAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Image as ImageIcon } from "lucide-react";
import type { UIReviewIssue } from "@/api/types";

function severityVariant(sev: string): "destructive" | "default" | "secondary" {
  if (sev === "error") return "destructive";
  if (sev === "warning") return "default";
  return "secondary";
}

export default function StylistReviewDetailPage() {
  const { reviewId = "" } = useParams();
  const queryClient = useQueryClient();
  const [selectedIssue, setSelectedIssue] = useState<string | null>(null);

  const { data: review, isLoading } = useQuery({
    queryKey: ["stylist-review", reviewId],
    queryFn: () => getUIReview(reviewId),
    enabled: !!reviewId,
  });

  const createTicket = useMutation({
    mutationFn: (issueId: string) => createIssueTicket(reviewId, issueId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["stylist-review", reviewId] });
    },
  });

  if (isLoading || !review) {
    return (
      <div className="p-6" data-testid="review-detail-page">
        <p className="text-muted-foreground">Loading review…</p>
      </div>
    );
  }

  const labels = Array.from(new Set(review.screenshots.map((s) => s.label || "view")));
  const defaultLabel = labels[0] ?? "view";

  return (
    <div className="space-y-6 p-6" data-testid="review-detail-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{review.page_name || review.page_url}</h1>
          <p className="text-sm text-muted-foreground">
            {review.review_type} · design {review.design_score.toFixed(1)}
            {review.accessibility_score != null && ` · a11y ${review.accessibility_score.toFixed(1)}`}
          </p>
        </div>
        <Badge variant={review.status === "completed" ? "secondary" : "destructive"}>
          {review.status}
        </Badge>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ImageIcon className="h-4 w-4" /> Screenshots
          </CardTitle>
        </CardHeader>
        <CardContent>
          {review.screenshots.length === 0 ? (
            <p className="text-sm text-muted-foreground" data-testid="no-screenshots">
              No screenshots captured.
            </p>
          ) : (
            <Tabs defaultValue={defaultLabel}>
              <TabsList>
                {labels.map((l) => (
                  <TabsTrigger key={l} value={l}>
                    {l}
                  </TabsTrigger>
                ))}
              </TabsList>
              {labels.map((l) => (
                <TabsContent key={l} value={l}>
                  {review.screenshots
                    .filter((s) => (s.label || "view") === l)
                    .map((s, i) => (
                      <figure key={i} className="space-y-1">
                        <img
                          src={s.url}
                          alt={`${review.page_name} ${l}`}
                          className="max-w-full rounded border"
                          data-testid="review-screenshot"
                          loading="lazy"
                        />
                        <figcaption className="text-xs text-muted-foreground">{s.viewport}</figcaption>
                      </figure>
                    ))}
                </TabsContent>
              ))}
            </Tabs>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Issues ({review.issues_found})</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {review.issues.length === 0 ? (
            <p className="text-sm text-muted-foreground" data-testid="no-issues">
              No issues found — this page passed all checks.
            </p>
          ) : (
            review.issues.map((issue: UIReviewIssue) => (
              <div
                key={issue.issue_id}
                className={`rounded border p-3 ${selectedIssue === issue.issue_id ? "ring-2 ring-primary" : ""}`}
                data-testid="review-issue"
                onClick={() => setSelectedIssue(issue.issue_id)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge variant={severityVariant(issue.severity)}>{issue.severity}</Badge>
                    <Badge variant="outline">{issue.category}</Badge>
                    <span className="font-medium">{issue.title}</span>
                  </div>
                  {issue.created_ticket_id ? (
                    <Badge variant="secondary" data-testid="issue-ticketed">
                      Ticket {issue.created_ticket_id}
                    </Badge>
                  ) : (
                    <Button
                      size="sm"
                      variant="outline"
                      data-testid="create-ticket-btn"
                      disabled={createTicket.isPending}
                      onClick={(e) => {
                        e.stopPropagation();
                        createTicket.mutate(issue.issue_id);
                      }}
                    >
                      Create Ticket
                    </Button>
                  )}
                </div>
                <p className="mt-2 text-sm text-muted-foreground">{issue.description}</p>
                {issue.suggestion && (
                  <p className="mt-1 text-sm">
                    <span className="font-medium">Suggestion:</span> {issue.suggestion}
                  </p>
                )}
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}
