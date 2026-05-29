import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listQuestions,
  featureQuestion,
  dismissQuestion,
  removeQuestion,
} from "@/api/endpoints/broadcastQA";
import { QAQuestionCard } from "./QAQuestionCard";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";

interface QAQueuePanelProps {
  sessionId: string;
}

export function QAQueuePanel({ sessionId }: QAQueuePanelProps) {
  const queryClient = useQueryClient();

  const pendingQuery = useQuery({
    queryKey: ["qa-questions", sessionId, "pending"],
    queryFn: () => listQuestions(sessionId, "pending"),
    refetchInterval: 10_000,
  });

  const answeredQuery = useQuery({
    queryKey: ["qa-questions", sessionId, "answered"],
    queryFn: () => listQuestions(sessionId, "answered"),
  });

  const featureMut = useMutation({
    mutationFn: (questionId: string) => featureQuestion(sessionId, questionId),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["qa-questions", sessionId] }),
  });

  const dismissMut = useMutation({
    mutationFn: (questionId: string) => dismissQuestion(sessionId, questionId),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["qa-questions", sessionId] }),
  });

  const removeMut = useMutation({
    mutationFn: (questionId: string) => removeQuestion(sessionId, questionId),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["qa-questions", sessionId] }),
  });

  const pending = pendingQuery.data?.questions ?? [];
  const answered = answeredQuery.data?.questions ?? [];

  return (
    <Tabs defaultValue="pending">
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
            <p className="text-sm text-muted-foreground p-4 text-center">
              No questions yet
            </p>
          ) : (
            pending.map((q) => (
              <QAQuestionCard
                key={q.question_id}
                question={q}
                onFeature={() => featureMut.mutate(q.question_id)}
                onDismiss={() => dismissMut.mutate(q.question_id)}
                onRemove={() => removeMut.mutate(q.question_id)}
                isModerator
              />
            ))
          )}
        </ScrollArea>
      </TabsContent>
      <TabsContent value="answered">
        <ScrollArea className="h-[400px]">
          {answered.length === 0 ? (
            <p className="text-sm text-muted-foreground p-4 text-center">
              No answered questions yet
            </p>
          ) : (
            answered.map((q) => (
              <QAQuestionCard
                key={q.question_id}
                question={q}
                isModerator={false}
              />
            ))
          )}
        </ScrollArea>
      </TabsContent>
    </Tabs>
  );
}
