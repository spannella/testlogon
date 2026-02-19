declare const self: DedicatedWorkerGlobalScope;

export {};

type ParseKind = "csv" | "excel" | "word";

type ParseRequest = {
  type: "parse";
  payload: {
    jobId: string;
    kind: ParseKind;
    fileName: string;
  };
};

type CancelRequest = {
  type: "cancel";
  payload: {
    jobId: string;
  };
};

type WorkerRequest = ParseRequest | CancelRequest;

const activeJobs = new Map<string, number>();

function clearJob(jobId: string) {
  const timer = activeJobs.get(jobId);
  if (timer != null) {
    clearTimeout(timer);
    activeJobs.delete(jobId);
  }
}

function postProgress(jobId: string, progress: number, stage: string) {
  self.postMessage({ type: "progress", payload: { jobId, progress, stage } });
}

function runScaffoldParse(jobId: string, kind: ParseKind, fileName: string) {
  const stages = [
    { progress: 10, stage: "queued" },
    { progress: 40, stage: "loading" },
    { progress: 75, stage: "analyzing" },
    { progress: 100, stage: "complete" },
  ];

  let idx = 0;
  const tick = () => {
    if (!activeJobs.has(jobId)) return;

    const current = stages[idx];
    postProgress(jobId, current?.progress ?? 100, current?.stage ?? "complete");

    if (idx >= stages.length - 1) {
      activeJobs.delete(jobId);
      self.postMessage({
        type: "done",
        payload: {
          jobId,
          kind,
          fileName,
          outcome: "not_enabled",
          message: "Heavy-format parser scaffold completed. Renderer will be enabled in a follow-up ticket.",
        },
      });
      return;
    }

    idx += 1;
    const timer = self.setTimeout(tick, 120);
    activeJobs.set(jobId, timer);
  };

  const timer = self.setTimeout(tick, 0);
  activeJobs.set(jobId, timer);
}

self.onmessage = (event: MessageEvent<WorkerRequest>) => {
  const data = event.data;

  if (data.type === "cancel") {
    const { jobId } = data.payload;
    if (activeJobs.has(jobId)) {
      clearJob(jobId);
      self.postMessage({ type: "canceled", payload: { jobId } });
    }
    return;
  }

  const { jobId, kind, fileName } = data.payload;
  try {
    clearJob(jobId);
    runScaffoldParse(jobId, kind, fileName);
  } catch (err) {
    clearJob(jobId);
    self.postMessage({
      type: "error",
      payload: {
        jobId,
        error: err instanceof Error ? err.message : "Preview parse scaffold failed",
      },
    });
  }
};
