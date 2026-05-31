import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { submitIdea, listIdeas } from "@/api/endpoints/pmAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Lightbulb } from "lucide-react";

export default function IdeaSubmissionPage() {
  const queryClient = useQueryClient();
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [lastId, setLastId] = useState<string | null>(null);

  const { data } = useQuery({
    queryKey: ["my-ideas"],
    queryFn: () => listIdeas({ limit: 50 }),
    staleTime: 10_000,
  });

  const submitMut = useMutation({
    mutationFn: () => submitIdea(title, description),
    onSuccess: (idea) => {
      setLastId(idea.idea_id);
      setTitle("");
      setDescription("");
      queryClient.invalidateQueries({ queryKey: ["my-ideas"] });
    },
  });

  const ideas = data?.ideas ?? [];

  return (
    <div data-testid="idea-submission-page" className="space-y-4 p-4">
      <div className="flex items-center gap-2">
        <Lightbulb className="h-6 w-6" />
        <h1 className="text-2xl font-bold">Submit a Product Idea</h1>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">New idea</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div>
            <Label>Title</Label>
            <Input
              data-testid="idea-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="A short, descriptive title"
            />
          </div>
          <div>
            <Label>Description</Label>
            <Textarea
              data-testid="idea-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={5}
              placeholder="Describe the problem, who it helps, and the desired outcome."
            />
          </div>
          <Button
            data-testid="idea-submit-btn"
            onClick={() => submitMut.mutate()}
            disabled={submitMut.isPending || title.trim().length < 3 || description.trim().length < 10}
          >
            Submit idea
          </Button>
          {lastId && (
            <p data-testid="idea-confirmation" className="text-sm text-green-600">
              Idea submitted! Your idea ID is {lastId}. The PM Agent will triage it shortly.
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Your ideas</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {ideas.length === 0 ? (
            <p className="text-muted-foreground">You haven't submitted any ideas yet.</p>
          ) : (
            ideas.map((i) => (
              <div key={i.idea_id} data-testid="my-idea-row" className="flex items-center justify-between border-b py-1">
                <span>{i.title}</span>
                <Badge variant="secondary">{i.status}</Badge>
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}
