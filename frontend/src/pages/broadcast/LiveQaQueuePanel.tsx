import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  answerLiveQaQuestion,
  dismissLiveQaQuestion,
  featureLiveQaQuestion,
  listLiveQaQuestions,
  pinLiveQaQuestion,
  removeLiveQaQuestion,
  upvoteLiveQaQuestion,
} from "@/api/endpoints/liveQa";
import { LiveQaQuestionCard } from "./LiveQaQuestionCard";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { LiveQaQuestion } from "@/api/types";

interface LiveQaQueuePanelProps {
  sessionId: string;
  isModerator?: boolean;
}

export function LiveQaQueuePanel({ sessionId, isModerator = true }: LiveQaQueuePanelProps) {
  const queryClient = useQueryClient();
  const invalidate = () =>
    queryClient.invalidateQueries({ queryKey: ["live-qa-questions", sessionId] });

  const pendingQuery = useQuery({
    queryKey: ["live-qa-questions", sessionId, "pending"],
    queryFn: () => listLiveQaQuestions(sessionId, "pending"),
    refetchInterval: 10_000,
  });

  const answeredQuery = useQuery({
    queryKey: ["live-qa-questions", sessionId, "answered"],
    queryFn: () => listLiveQaQuestions(sessionId, "answered"),
  });

  const mut = (fn: (sid: string, qid: string) => Promise<unknown>) =>
    useMutation({
      mutationFn: (questionId: string) => fn(sessionId, questionId),
      onSuccess: invalidate,
    });

  const voteMut = mut(upvoteLiveQaQuestion);
  const featureMut = mut(featureLiveQaQuestion);
  const answerMut = mut(answerLiveQaQuestion);
  const dismissMut = mut(dismissLiveQaQuestion);
  const removeMut = mut(removeLiveQaQuestion);
  const pinMut = useMutation({
    mutationFn: (q: LiveQaQuestion) => pinLiveQaQuestion(sessionId, q.question_id, !q.pinned),
    onSuccess: invalidate,
  });

  const pending = pendingQuery.data?.questions ?? [];
  const answered = answeredQuery.data?.questions ?? [];

  return (
    <Tabs defaultValue="pending" data-testid="live-qa-queue-panel">
      <TabsList className="w-full">
        <TabsTrigger value="pending" className="flex-1">
          Pending ({pending.length})
        </TabsTrigger>
        <TabsTrigger value="answered" className="flex-1">
          Answered ({answered.length})
        </TabsTrigger>
      </TabsList>
      <TabsContent value="pending">
        <ScrollArea className="h-[400px]">
          {pending.length === 0 ? (
            <p className="p-4 text-center text-sm text-muted-foreground">No questions yet</p>
          ) : (
            pending.map((q) => (
              <LiveQaQuestionCard
                key={q.question_id}
                question={q}
                isModerator={isModerator}
                onVote={() => voteMut.mutate(q.question_id)}
                onFeature={() => featureMut.mutate(q.question_id)}
                onAnswer={() => answerMut.mutate(q.question_id)}
                onDismiss={() => dismissMut.mutate(q.question_id)}
                onPin={() => pinMut.mutate(q)}
                onRemove={() => removeMut.mutate(q.question_id)}
              />
            ))
          )}
        </ScrollArea>
      </TabsContent>
      <TabsContent value="answered">
        <ScrollArea className="h-[400px]">
          {answered.length === 0 ? (
            <p className="p-4 text-center text-sm text-muted-foreground">No answered questions</p>
          ) : (
            answered.map((q) => (
              <LiveQaQuestionCard key={q.question_id} question={q} isModerator={false} />
            ))
          )}
        </ScrollArea>
      </TabsContent>
    </Tabs>
  );
}
