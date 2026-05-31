import { useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getLiveQaFeatured, getLiveQaMode } from "@/api/endpoints/liveQa";
import { LiveQaModeToggle } from "./LiveQaModeToggle";
import { LiveQaQuestionInput } from "./LiveQaQuestionInput";
import { LiveQaQueuePanel } from "./LiveQaQueuePanel";
import { LiveQaFeaturedOverlay } from "./LiveQaFeaturedOverlay";
import { LiveQaStatsPanel } from "./LiveQaStatsPanel";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { MessageCircleQuestion } from "lucide-react";

/**
 * Live Q&A page for a broadcast session. Shows the audience submit/vote view
 * and (for the host) the moderation queue + engagement stats.
 *
 * Route: /broadcast/:sessionId/live-qa
 */
export default function LiveQaPage() {
  const { sessionId = "" } = useParams<{ sessionId: string }>();
  const [showHost, setShowHost] = useState(true);

  const modeQuery = useQuery({
    queryKey: ["live-qa-mode", sessionId],
    queryFn: () => getLiveQaMode(sessionId),
    enabled: !!sessionId,
  });

  const featuredQuery = useQuery({
    queryKey: ["live-qa-featured", sessionId],
    queryFn: () => getLiveQaFeatured(sessionId),
    enabled: !!sessionId,
    refetchInterval: 8_000,
  });

  const enabled = modeQuery.data?.qa_mode_enabled ?? false;
  const featured = featuredQuery.data ?? null;

  return (
    <div className="mx-auto max-w-3xl space-y-4 p-4" data-testid="live-qa-page">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-xl font-semibold">
          <MessageCircleQuestion className="h-5 w-5" /> Live Q&amp;A
        </h1>
        <Button variant="outline" size="sm" onClick={() => setShowHost((v) => !v)}>
          {showHost ? "Audience view" : "Host view"}
        </Button>
      </div>

      <LiveQaModeToggle sessionId={sessionId} />

      {featured && featured.question_id && <LiveQaFeaturedOverlay question={featured} />}

      {!enabled ? (
        <Card>
          <CardContent className="p-6 text-center text-sm text-muted-foreground">
            Q&amp;A mode is currently off. Turn it on to collect audience questions.
          </CardContent>
        </Card>
      ) : showHost ? (
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Question Queue</CardTitle>
            </CardHeader>
            <CardContent>
              <LiveQaQueuePanel sessionId={sessionId} />
            </CardContent>
          </Card>
          <LiveQaStatsPanel sessionId={sessionId} />
        </div>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Ask a Question</CardTitle>
          </CardHeader>
          <CardContent>
            <LiveQaQuestionInput sessionId={sessionId} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
