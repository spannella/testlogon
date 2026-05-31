import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Lightbulb, RefreshCw } from "lucide-react";
import {
  listFeatureIdeas,
  approveIdea,
  triggerReview,
} from "@/api/endpoints/productAgent";
import type { FeatureIdea, PmIdeaStatus } from "@/api/types";
import IdeaDetailDialog from "./IdeaDetailDialog";
import PmConfigPanel from "./PmConfigPanel";
import PreferenceDashboard from "./PreferenceDashboard";

const STATUSES: { value: PmIdeaStatus; label: string }[] = [
  { value: "pending", label: "Pending" },
  { value: "approved", label: "Approved" },
  { value: "rejected", label: "Rejected" },
  { value: "archived", label: "Archived" },
];

function IdeaGrid({
  status,
  onOpen,
}: {
  status: PmIdeaStatus;
  onOpen: (idea: FeatureIdea) => void;
}) {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["pm-ideas", status],
    queryFn: () => listFeatureIdeas(status),
  });

  const approveMut = useMutation({
    mutationFn: (id: string) => approveIdea(id),
    onSuccess: () => {
      toast.success("Idea approved — ticket created");
      queryClient.invalidateQueries({ queryKey: ["pm-ideas"] });
    },
    onError: (e: Error) => toast.error(e.message || "Approve failed"),
  });

  const ideas = data?.ideas ?? [];

  if (isLoading) {
    return <p className="text-sm text-muted-foreground">Loading ideas…</p>;
  }

  if (ideas.length === 0) {
    return (
      <p className="text-sm text-muted-foreground" data-testid="ideas-empty">
        No {status} ideas.
      </p>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
      {ideas.map((idea) => (
        <Card
          key={idea.idea_id}
          data-testid={`idea-card-${idea.idea_id}`}
          className="cursor-pointer transition hover:shadow-md"
          onClick={() => onOpen(idea)}
        >
          <CardHeader>
            <span className="font-semibold">{idea.title}</span>
            <div className="mt-2 flex flex-wrap gap-2">
              <Badge data-testid={`idea-category-${idea.idea_id}`}>{idea.category}</Badge>
              <Badge variant="secondary" data-testid={`idea-priority-${idea.idea_id}`}>
                {idea.priority_suggestion}
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <p className="line-clamp-3 text-sm text-muted-foreground">{idea.user_impact}</p>
          </CardContent>
          {idea.status === "pending" && (
            <CardFooter className="gap-2">
              <Button
                size="sm"
                data-testid={`idea-approve-quick-${idea.idea_id}`}
                onClick={(e) => {
                  e.stopPropagation();
                  approveMut.mutate(idea.idea_id);
                }}
              >
                Approve
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={(e) => {
                  e.stopPropagation();
                  onOpen(idea);
                }}
              >
                Reject
              </Button>
            </CardFooter>
          )}
        </Card>
      ))}
    </div>
  );
}

export default function FeatureIdeasPage() {
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<FeatureIdea | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);

  const triggerMut = useMutation({
    mutationFn: () => triggerReview(),
    onSuccess: () => {
      toast.success("Review triggered");
      queryClient.invalidateQueries({ queryKey: ["pm-ideas"] });
    },
    onError: (e: Error) => toast.error(e.message || "Trigger failed"),
  });

  const openIdea = (idea: FeatureIdea) => {
    setSelected(idea);
    setDialogOpen(true);
  };

  return (
    <div className="space-y-6 p-4" data-testid="feature-ideas-page">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Lightbulb className="h-6 w-6" />
          <h1 className="text-2xl font-semibold">Feature Ideas</h1>
        </div>
        <Button
          variant="outline"
          onClick={() => triggerMut.mutate()}
          disabled={triggerMut.isPending}
          data-testid="pm-trigger-review"
        >
          <RefreshCw className="mr-2 h-4 w-4" />
          Trigger Review
        </Button>
      </div>

      <Tabs defaultValue="pending">
        <TabsList>
          {STATUSES.map((s) => (
            <TabsTrigger key={s.value} value={s.value} data-testid={`tab-${s.value}`}>
              {s.label}
            </TabsTrigger>
          ))}
        </TabsList>
        {STATUSES.map((s) => (
          <TabsContent key={s.value} value={s.value} className="mt-4">
            <IdeaGrid status={s.value} onOpen={openIdea} />
          </TabsContent>
        ))}
      </Tabs>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <PreferenceDashboard />
        <PmConfigPanel />
      </div>

      <IdeaDetailDialog
        idea={selected}
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
      />
    </div>
  );
}
