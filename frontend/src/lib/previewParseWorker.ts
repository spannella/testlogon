export type HeavyPreviewKind = "csv" | "excel" | "word";

export type PreviewParseProgress = {
  jobId: string;
  progress: number;
  stage: string;
};

export type PreviewParseDone = {
  jobId: string;
  kind: HeavyPreviewKind;
  fileName: string;
  outcome: "not_enabled";
  message: string;
};

export type PreviewParseError = {
  jobId: string;
  error: string;
};

type PreviewParseCallbacks = {
  onProgress?: (payload: PreviewParseProgress) => void;
  onDone?: (payload: PreviewParseDone) => void;
  onCanceled?: (jobId: string) => void;
  onError?: (payload: PreviewParseError) => void;
};

export type PreviewParseJob = {
  jobId: string;
  cancel: () => void;
  dispose: () => void;
};

export function startPreviewParseJob(
  kind: HeavyPreviewKind,
  fileName: string,
  callbacks: PreviewParseCallbacks,
): PreviewParseJob {
  const jobId = `${kind}:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;
  const worker = new Worker(new URL("../workers/previewParse.worker.ts", import.meta.url), { type: "module" });

  worker.onmessage = (event: MessageEvent) => {
    const message = event.data as { type: string; payload?: unknown };
    if (!message?.type) return;

    switch (message.type) {
      case "progress":
        callbacks.onProgress?.(message.payload as PreviewParseProgress);
        return;
      case "done":
        callbacks.onDone?.(message.payload as PreviewParseDone);
        return;
      case "canceled": {
        const payload = message.payload as { jobId: string };
        callbacks.onCanceled?.(payload.jobId);
        return;
      }
      case "error":
        callbacks.onError?.(message.payload as PreviewParseError);
        return;
      default:
        return;
    }
  };

  worker.postMessage({ type: "parse", payload: { jobId, kind, fileName } });

  const cancel = () => {
    worker.postMessage({ type: "cancel", payload: { jobId } });
  };

  const dispose = () => {
    worker.terminate();
  };

  return { jobId, cancel, dispose };
}
