import type { QAQuestion } from "@/api/types";
import { Button } from "@/components/ui/button";
import { ThumbsUp, Star, X, Trash2 } from "lucide-react";

interface QAQuestionCardProps {
  question: QAQuestion;
  onFeature?: () => void;
  onDismiss?: () => void;
  onRemove?: () => void;
  onUpvote?: () => void;
  isModerator?: boolean;
}

export function QAQuestionCard({
  question,
  onFeature,
  onDismiss,
  onRemove,
  onUpvote,
  isModerator = false,
}: QAQuestionCardProps) {
  return (
    <div className="border-b p-3 hover:bg-muted/50" data-question-id={question.question_id}>
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <p className="text-xs font-medium text-muted-foreground">
            {question.submitter_display_name}
          </p>
          <p className="text-sm mt-0.5">{question.text}</p>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          {onUpvote && (
            <Button variant="ghost" size="sm" onClick={onUpvote} className="h-7 px-2">
              <ThumbsUp className="h-3.5 w-3.5 mr-1" />
              <span className="text-xs">{question.upvote_count}</span>
            </Button>
          )}
        </div>
      </div>
      {isModerator && question.status === "pending" && (
        <div className="flex items-center gap-1 mt-2">
          {onFeature && (
            <Button variant="outline" size="sm" onClick={onFeature} className="h-7 text-xs">
              <Star className="h-3 w-3 mr-1" />
              Feature
            </Button>
          )}
          {onDismiss && (
            <Button variant="ghost" size="sm" onClick={onDismiss} className="h-7 text-xs">
              <X className="h-3 w-3 mr-1" />
              Dismiss
            </Button>
          )}
          {onRemove && (
            <Button variant="ghost" size="sm" onClick={onRemove} className="h-7 text-xs text-destructive">
              <Trash2 className="h-3 w-3 mr-1" />
              Remove
            </Button>
          )}
        </div>
      )}
      {question.status === "answered" && (
        <p className="text-xs text-green-600 mt-1">Answered</p>
      )}
      {question.status === "featured" && (
        <p className="text-xs text-primary font-medium mt-1">Currently Featured</p>
      )}
    </div>
  );
}
