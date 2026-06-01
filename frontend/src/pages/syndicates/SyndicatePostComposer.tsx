import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent } from "@/components/ui/card";
import { createSyndicatePost } from "@/api/endpoints/syndicateFeed";

interface SyndicatePostComposerProps {
  syndicateId: string;
}

export function SyndicatePostComposer({ syndicateId }: SyndicatePostComposerProps) {
  const [text, setText] = useState("");
  const [membersOnly, setMembersOnly] = useState(false);
  const qc = useQueryClient();

  const mutation = useMutation({
    mutationFn: () =>
      createSyndicatePost(syndicateId, {
        text: text.trim(),
        visibility: membersOnly ? "members_only" : "public",
      }),
    onSuccess: () => {
      setText("");
      setMembersOnly(false);
      qc.invalidateQueries({ queryKey: ["syndicate-feed", syndicateId] });
      toast.success("Post published");
    },
    onError: () => toast.error("Failed to publish post"),
  });

  const disabled = mutation.isPending || text.trim().length === 0;

  return (
    <Card data-testid="syndicate-post-composer">
      <CardContent className="space-y-3 pt-4">
        <Textarea
          placeholder="Share something with the syndicate..."
          value={text}
          maxLength={5000}
          onChange={(e) => setText(e.target.value)}
          data-testid="syndicate-post-text"
        />
        <div className="flex items-center justify-between">
          <label className="flex items-center gap-2 text-sm" htmlFor="synd-visibility-toggle">
            <Switch
              id="synd-visibility-toggle"
              checked={membersOnly}
              onCheckedChange={setMembersOnly}
              data-testid="syndicate-visibility-toggle"
            />
            <span data-testid="syndicate-visibility-label">
              {membersOnly ? "Members Only" : "Public"}
            </span>
          </label>
          <Button
            onClick={() => mutation.mutate()}
            disabled={disabled}
            data-testid="syndicate-post-submit"
          >
            {mutation.isPending ? "Posting..." : "Post"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

export default SyndicatePostComposer;
