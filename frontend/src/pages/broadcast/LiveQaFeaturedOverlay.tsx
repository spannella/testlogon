import { Card, CardContent } from "@/components/ui/card";
import { MessageCircleQuestion, ThumbsUp } from "lucide-react";
import type { LiveQaQuestion } from "@/api/types";

interface LiveQaFeaturedOverlayProps {
  question: LiveQaQuestion;
}

export function LiveQaFeaturedOverlay({ question }: LiveQaFeaturedOverlayProps) {
  return (
    <Card
      className="border-primary/50 bg-background/90 backdrop-blur-sm"
      data-testid="live-qa-featured-overlay"
    >
      <CardContent className="p-3">
        <div className="flex items-start gap-2">
          <MessageCircleQuestion className="mt-0.5 h-5 w-5 shrink-0 text-primary" />
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-primary">
              {question.submitter_display_name} asks:
            </p>
            <p className="mt-1 break-words text-sm">{question.text}</p>
            <div className="mt-1 flex items-center gap-1 text-xs text-muted-foreground">
              <ThumbsUp className="h-3 w-3" />
              <span>{question.vote_count}</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
