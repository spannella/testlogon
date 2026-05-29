import { Card, CardContent } from "@/components/ui/card";
import { MessageCircleQuestion, ThumbsUp } from "lucide-react";
import type { QAQuestion } from "@/api/types";

interface QAFeaturedOverlayProps {
  question: QAQuestion;
}

export function QAFeaturedOverlay({ question }: QAFeaturedOverlayProps) {
  return (
    <Card className="absolute top-4 left-4 right-4 z-10 bg-background/90 backdrop-blur-sm border-primary/50">
      <CardContent className="p-3">
        <div className="flex items-start gap-2">
          <MessageCircleQuestion className="h-5 w-5 text-primary mt-0.5 shrink-0" />
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-primary">
              {question.submitter_display_name} asks:
            </p>
            <p className="text-sm mt-1">{question.text}</p>
            <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
              <ThumbsUp className="h-3 w-3" />
              <span>{question.upvote_count}</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
