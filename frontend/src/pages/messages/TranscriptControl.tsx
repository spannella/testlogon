import * as React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { FileText, Loader2 } from "lucide-react";
import { transcribeMessage } from "@/api/endpoints/messagingAi";
import { isMessagingTranscriptionEnabled } from "@/lib/featureFlags";
import { ApiError } from "@/api/client";

/**
 * MVA-008: "Show transcript" affordance for voice / voicemail messages.
 *
 * - If the message already carries a persisted `transcript` (from a prior
 *   transcription by any participant), render it directly behind a toggle.
 * - Otherwise the first click calls the MVA-007 endpoint, then renders the
 *   returned transcript and invalidates the messages query so the persisted
 *   transcript shows for everyone afterwards.
 *
 * The control is hidden when `messaging_transcription_enabled` is off; if the
 * server flag is off the endpoint 404s and we surface a toast.
 */
export function TranscriptControl({
  conversationId,
  messageId,
  existingTranscript,
  existingLang,
}: {
  conversationId: string;
  messageId: string;
  existingTranscript?: string;
  existingLang?: string;
}) {
  const queryClient = useQueryClient();
  const [transcript, setTranscript] = React.useState<string | null>(existingTranscript ?? null);
  const [lang, setLang] = React.useState<string | null>(existingLang ?? null);
  const [shown, setShown] = React.useState<boolean>(Boolean(existingTranscript));

  React.useEffect(() => {
    if (existingTranscript) {
      setTranscript(existingTranscript);
      setLang(existingLang ?? null);
    }
  }, [existingTranscript, existingLang]);

  const mut = useMutation({
    mutationFn: () => transcribeMessage(conversationId, messageId),
    onSuccess: (resp) => {
      setTranscript(resp.transcript);
      setLang(resp.transcript_lang || null);
      setShown(true);
      void queryClient.invalidateQueries({ queryKey: ["messages", conversationId] });
    },
    onError: (err) => {
      if (err instanceof ApiError && err.status === 404) {
        toast.error("Transcription is not enabled on this server");
      } else if (err instanceof ApiError && err.status === 429) {
        toast.error("Too many transcription requests — try again shortly");
      } else if (err instanceof ApiError && err.status === 400) {
        toast.error("This message cannot be transcribed");
      } else {
        toast.error("Failed to transcribe voice message");
      }
    },
  });

  if (!isMessagingTranscriptionEnabled()) return null;

  const handleClick = () => {
    if (transcript) {
      setShown((s) => !s);
      return;
    }
    mut.mutate();
  };

  return (
    <div className="mt-1.5">
      <button
        type="button"
        className="flex items-center gap-1 text-xs font-medium text-primary hover:underline disabled:opacity-60"
        onClick={handleClick}
        disabled={mut.isPending}
        data-testid="show-transcript"
      >
        {mut.isPending ? (
          <Loader2 className="h-3 w-3 animate-spin" />
        ) : (
          <FileText className="h-3 w-3" />
        )}
        {transcript ? (shown ? "Hide transcript" : "Show transcript") : "Show transcript"}
      </button>
      {transcript && shown && (
        <div className="mt-1 rounded-md border-l-2 border-primary/40 bg-muted/30 px-2 py-1.5">
          {lang && (
            <div className="mb-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
              Transcript · {lang}
            </div>
          )}
          <p className="whitespace-pre-wrap break-words text-sm select-text" data-testid="transcript-text">
            {transcript}
          </p>
        </div>
      )}
    </div>
  );
}
