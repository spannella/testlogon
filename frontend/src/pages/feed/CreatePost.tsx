import { useState, useRef, useMemo, useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useOfflineStore } from "@/stores/offlineStore";
import { Send, ImagePlus, X, Loader2, FolderOpen, Lock, Paperclip, Clock, Globe } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  createPost,
  getFeedCapabilities,
  uploadPostImage,
  createDraftPost,
  listDraftPosts,
  getDraftPost,
  updateDraftPost,
  deleteDraftPost,
  publishDraftPost,
} from "@/api/endpoints/newsfeed";
import { downloadUrl, getFileInfo } from "@/api/endpoints/files";
import { ApiError } from "@/api/client";
import { FilePickerDialog } from "@/pages/messages/FilePickerDialog";
import { newsfeedSchedulingUiEnabled } from "@/lib/featureFlags";
import { MarkdownComposer, type EditorMode, type RichDoc, buildContentPayload } from "./MarkdownComposer";
import type { CreateDraftPostReq, DraftPost, FileEntry } from "@/api/types";
import { reportDraftLifecycleEvent } from "@/lib/newsfeedDraftTelemetry";
import { isNewsfeedDraftsEnabled } from "@/lib/featureFlags";
import { invalidateFeedCaches } from "@/lib/feedCacheInvalidation";

const MAX_IMAGES = 10;
const MAX_FILES = 5;
const AUTOSAVE_DEBOUNCE_MS = 2000;
const AUTOSAVE_RETRY_BASE_MS = 1500;
const AUTOSAVE_MAX_RETRIES = 3;
const LEGACY_DRAFT_MIGRATION_FLAG = "newsfeed_draft_migration_v1_done";
const LEGACY_DRAFT_KEYS = [
  "newsfeed_create_post_draft",
  "newsfeed_createpost_draft",
  "newsfeed_draft_post",
  "newsfeed.draft",
];

type DraftSaveMode = "manual" | "autosave" | "pre_publish";
type PublishDraftTarget = { draftId: string; updatedAt?: string };

function parseLegacyDraftValue(raw: string): CreateDraftPostReq[] {
  try {
    const parsed = JSON.parse(raw);
    const items = Array.isArray(parsed) ? parsed : [parsed];
    return items.flatMap((item) => {
      if (!item || typeof item !== "object") return [];
      const obj = item as Record<string, unknown>;
      const bodyPlain = typeof obj.body_plain === "string"
        ? obj.body_plain
        : typeof obj.body === "string"
          ? obj.body
          : typeof obj.text === "string"
            ? obj.text
            : "";
      const bodyMarkdown = typeof obj.body_markdown === "string" ? obj.body_markdown : undefined;
      const bodyRich = obj.body_rich && typeof obj.body_rich === "object" ? obj.body_rich as Record<string, unknown> : undefined;
      const bodyFormat = obj.body_format === "markdown" || obj.body_format === "rich" || obj.body_format === "plain"
        ? obj.body_format
        : bodyRich
          ? "rich"
          : bodyMarkdown
            ? "markdown"
            : "plain";
      const imageUrls = Array.isArray(obj.image_urls) ? obj.image_urls.filter((v): v is string => typeof v === "string") : [];
      const filePaths = Array.isArray(obj.file_paths) ? obj.file_paths.filter((v): v is string => typeof v === "string") : [];
      const unlockPrice = typeof obj.unlock_price_cents === "number" ? obj.unlock_price_cents : undefined;
      if (!bodyPlain.trim() && imageUrls.length === 0 && filePaths.length === 0) return [];
      return [{
        body_plain: bodyPlain,
        ...(bodyMarkdown ? { body_markdown: bodyMarkdown } : {}),
        ...(bodyRich ? { body_rich: bodyRich } : {}),
        body_format: bodyFormat,
        ...(imageUrls.length > 0 ? { image_urls: imageUrls } : {}),
        ...(filePaths.length > 0 ? { file_paths: filePaths } : {}),
        ...(unlockPrice && unlockPrice > 0 ? { unlock_price_cents: unlockPrice } : {}),
      }];
    });
  } catch {
    return [];
  }
}

function telemetryReasonCodeFromError(err: unknown): string {
  if (err instanceof ApiError) {
    const body = err.body as { detail?: unknown } | undefined;
    const detail = body?.detail;
    if (detail && typeof detail === "object" && "code" in detail) {
      const code = (detail as { code?: unknown }).code;
      if (typeof code === "string" && code.trim()) return code.slice(0, 120);
    }
    if (typeof err.status === "number" && err.status > 0) {
      return `http_${err.status}`;
    }
  }
  if (err instanceof Error) {
    const normalized = err.message.trim().toLowerCase().replace(/[^a-z0-9_]+/g, "_").replace(/^_+|_+$/g, "");
    return (normalized || "unknown_error").slice(0, 120);
  }
  return "unknown_error";
}

export function CreatePost() {
  const draftsFeatureEnabled = isNewsfeedDraftsEnabled();
  const schedulingUiEnabled = newsfeedSchedulingUiEnabled;
  const queryClient = useQueryClient();
  const addToQueue = useOfflineStore((s) => s.addToQueue);
  const isOnline = useOfflineStore((s) => s.isOnline);
  const fileRef = useRef<HTMLInputElement>(null);
  const [body, setBody] = useState("");
  const [editorMode, setEditorMode] = useState<EditorMode>("plain");
  const [richDoc, setRichDoc] = useState<RichDoc | null>(null);
  const [imageUrls, setImageUrls] = useState<string[]>([]);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [filePickerOpen, setFilePickerOpen] = useState(false);
  const [attachFilePickerOpen, setAttachFilePickerOpen] = useState(false);
  const [pendingFiles, setPendingFiles] = useState<FileEntry[]>([]);
  const [lockEnabled, setLockEnabled] = useState(false);
  const [lockPrice, setLockPrice] = useState("");
  const [activeDraftId, setActiveDraftId] = useState<string | null>(null);
  const [activeDraftUpdatedAt, setActiveDraftUpdatedAt] = useState<string | null>(null);
  const [activeDraftBaseline, setActiveDraftBaseline] = useState<string | null>(null);
  const [lastSavedSnapshot, setLastSavedSnapshot] = useState<string | null>(null);
  const [autosaveStatus, setAutosaveStatus] = useState<"idle" | "saving" | "retrying" | "saved" | "failed" | "offline" | "conflict">("idle");
  const [legacyMigrationRan, setLegacyMigrationRan] = useState(false);
  const autosaveDebounceRef = useRef<number | null>(null);
  const autosaveRetryRef = useRef<number | null>(null);
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const [scheduleTimezone, setScheduleTimezone] = useState(() => Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC");
  const [scheduledInput, setScheduledInput] = useState<string>("");
  const [scheduledAt, setScheduledAt] = useState<Date | null>(null);
  const [unlockLimitEnabled, setUnlockLimitEnabled] = useState(false);
  const [unlockLimit, setUnlockLimit] = useState("");
  const [unlockLimitError, setUnlockLimitError] = useState<string | null>(null);
  const { data: capabilities } = useQuery({
    queryKey: ["feed", "capabilities"],
    queryFn: getFeedCapabilities,
    staleTime: 60_000,
  });
  const unlockLimitFeatureEnabled = capabilities?.unlock_limit_enabled ?? false;

  const parseDateTimeInTz = (localStr: string, tz: string): Date => {
    const [datePart, timePart] = localStr.split("T");
    const [y, m, d] = (datePart || "").split("-").map(Number);
    const [hh, mm] = (timePart || "").split(":").map(Number);
    const utcGuess = new Date(Date.UTC(y, (m || 1) - 1, d || 1, hh || 0, mm || 0, 0));
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone: tz,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).formatToParts(utcGuess);
    const get = (type: string) => Number(parts.find((p) => p.type === type)?.value ?? "0");
    const tzAsUtc = Date.UTC(get("year"), get("month") - 1, get("day"), get("hour"), get("minute"), 0);
    const targetAsUtc = Date.UTC(y, (m || 1) - 1, d || 1, hh || 0, mm || 0, 0);
    return new Date(utcGuess.getTime() + (targetAsUtc - tzAsUtc));
  };

  const unlockPriceCents = (() => {
    if (!lockEnabled || !lockPrice.trim()) return undefined;
    const cents = Math.round(parseFloat(lockPrice) * 100);
    return isNaN(cents) || cents <= 0 ? undefined : cents;
  })();
  const parsedUnlockLimit = (() => {
    if (!lockEnabled || !unlockLimitEnabled || !unlockLimitFeatureEnabled) return undefined;
    const n = Number.parseInt(unlockLimit, 10);
    if (!Number.isFinite(n) || n < 1) return undefined;
    return n;
  })();

  const validateUnlockControls = () => {
    if (lockEnabled && !unlockPriceCents) {
      toast.error("Enter a valid lock price greater than $0");
      return false;
    }
    if (lockEnabled && unlockLimitEnabled && !parsedUnlockLimit) {
      setUnlockLimitError("Unlock limit must be a whole number greater than 0.");
      return false;
    }
    setUnlockLimitError(null);
    return true;
  };

  const getComposerSnapshot = () =>
    JSON.stringify({
      body,
      editorMode,
      richDoc,
      imageUrls,
      filePaths: pendingFiles.map((f) => f.path),
      unlockPriceCents: unlockPriceCents ?? null,
    });
  const composerSnapshot = useMemo(getComposerSnapshot, [body, editorMode, richDoc, imageUrls, pendingFiles, unlockPriceCents]);

  const buildDraftPayload = () => ({
    ...buildContentPayload(body, editorMode, richDoc),
    ...(imageUrls.length > 0 ? { image_urls: imageUrls } : {}),
    ...(pendingFiles.length > 0 ? { file_paths: pendingFiles.map((f) => f.path) } : {}),
    ...(unlockPriceCents ? { unlock_price_cents: unlockPriceCents } : {}),
  });

  const hydrateFromDraft = async (draft: DraftPost) => {
    const mode = draft.body_format ?? "plain";
    const plainBody = draft.body_plain ?? draft.body ?? "";
    const markdownBody = draft.body_markdown ?? plainBody;

    if (mode === "markdown") {
      setEditorMode("markdown");
      setBody(markdownBody);
      setRichDoc(null);
    } else if (mode === "rich") {
      setEditorMode("rich");
      setBody(plainBody);
      setRichDoc((draft.body_rich as RichDoc | null) ?? null);
    } else {
      setEditorMode("plain");
      setBody(plainBody);
      setRichDoc(null);
    }

    setImageUrls(draft.image_urls ?? []);
    const rawFilePaths = draft.file_paths ?? [];
    const validatedFiles = await Promise.all(rawFilePaths.map(async (path) => {
      try {
        const info = await getFileInfo(path);
        return {
          path,
          name: info.name ?? path.split("/").filter(Boolean).pop() ?? path,
          type: "file" as const,
          content_type: info.content_type,
        };
      } catch {
        return null;
      }
    }));
    const availableFiles = validatedFiles.filter((f): f is FileEntry => Boolean(f));
    const missingCount = rawFilePaths.length - availableFiles.length;
    setPendingFiles(availableFiles);
    if (missingCount > 0) {
      toast.info(`${missingCount} draft attachment${missingCount > 1 ? "s were" : " was"} unavailable and removed from composer`);
    }

    const cents = draft.unlock_price_cents ?? 0;
    setLockEnabled(cents > 0);
    setLockPrice(cents > 0 ? (cents / 100).toFixed(2) : "");
    setActiveDraftId(draft.draft_id);
    setActiveDraftUpdatedAt(draft.updated_at ?? null);

    const snapshot = JSON.stringify({
      body: mode === "markdown" ? markdownBody : plainBody,
      editorMode: mode,
      richDoc: (draft.body_rich as RichDoc | null) ?? null,
      imageUrls: draft.image_urls ?? [],
      filePaths: draft.file_paths ?? [],
      unlockPriceCents: draft.unlock_price_cents ?? null,
    });
    setActiveDraftBaseline(snapshot);
    setLastSavedSnapshot(snapshot);
    setAutosaveStatus("saved");
  };

  const resetComposer = () => {
    setBody("");
    setEditorMode("plain");
    setRichDoc(null);
    setImageUrls([]);
    setPendingFiles([]);
    setLockEnabled(false);
    setLockPrice("");
    setActiveDraftId(null);
    setActiveDraftUpdatedAt(null);
    setActiveDraftBaseline(null);
    setLastSavedSnapshot(null);
    setAutosaveStatus("idle");
    setScheduleOpen(false);
    setScheduledInput("");
    setScheduledAt(null);
    setUnlockLimitEnabled(false);
    setUnlockLimit("");
    setUnlockLimitError(null);
  };

  const draftsQuery = useQuery({
    queryKey: ["feed-drafts"],
    queryFn: () => listDraftPosts(undefined, 50),
    enabled: draftsFeatureEnabled,
  });

  const mutation = useMutation({
    mutationFn: (target?: PublishDraftTarget) => {
      const draftId = target?.draftId ?? activeDraftId ?? null;
      const draftUpdatedAt = target?.updatedAt ?? activeDraftUpdatedAt ?? undefined;
      if (draftsFeatureEnabled && draftId) {
        return publishDraftPost(draftId, false, draftUpdatedAt);
      }
      return createPost({
        ...buildContentPayload(body, editorMode, richDoc),
        ...(imageUrls.length > 0 ? { image_urls: imageUrls } : {}),
        ...(pendingFiles.length > 0 ? { file_paths: pendingFiles.map((f) => f.path) } : {}),
        ...(unlockPriceCents ? { unlock_price_cents: unlockPriceCents } : {}),
        ...(schedulingUiEnabled && scheduledAt
          ? {
              publish_at: Math.floor(scheduledAt.getTime() / 1000),
              schedule_timezone: scheduleTimezone,
              scheduled_at_local: scheduledInput || undefined,
            }
          : {}),
        ...(parsedUnlockLimit ? { unlock_limit: parsedUnlockLimit } : {}),
      });
    },
    onSuccess: async (resp, target) => {
      await invalidateFeedCaches(queryClient, resp.author_id);
      if (schedulingUiEnabled) {
        queryClient.invalidateQueries({ queryKey: ["scheduled-posts"] });
      }
      const publishedDraftId = target?.draftId ?? activeDraftId;
      if (draftsFeatureEnabled && publishedDraftId) {
        queryClient.setQueryData<{ items: DraftPost[]; next_cursor?: string } | undefined>(["feed-drafts"], (prev) => {
          if (!prev) return prev;
          return { ...prev, items: prev.items.filter((d) => d.draft_id !== publishedDraftId) };
        });
        queryClient.invalidateQueries({ queryKey: ["feed-drafts"] });
        reportDraftLifecycleEvent("publish_from_draft", "success");
      }
      resetComposer();
      toast.success(resp.status === "scheduled" ? "Post scheduled" : "Post published");
    },
    onError: (err: unknown, target) => {
      if (err instanceof ApiError && err.status === 409) {
        queryClient.invalidateQueries({ queryKey: ["feed-drafts"] });
        reportDraftLifecycleEvent("publish_from_draft", "fail", "version_conflict");
        toast.error("Draft changed on another session. Reloading latest draft...");
        const staleDraftId = target?.draftId ?? activeDraftId;
        if (staleDraftId) {
          void getDraftPost(staleDraftId)
            .then((freshDraft) => hydrateFromDraft(freshDraft))
            .then(() => {
              toast.success("Latest draft loaded. Review changes and publish again.");
            })
            .catch(() => {
              toast.error("Could not reload latest draft. Please load it manually from Saved drafts.");
            });
        }
        return;
      }
      if (draftsFeatureEnabled && (target?.draftId ?? activeDraftId)) {
        reportDraftLifecycleEvent("publish_from_draft", "fail", telemetryReasonCodeFromError(err));
      }
      const msg = err instanceof Error ? err.message : "Failed to create post";
      toast.error(msg);
    },
  });

  const saveDraftMutation = useMutation({
    mutationFn: async ({ mode }: { mode: DraftSaveMode }) => {
      const payload = buildDraftPayload();
      if (activeDraftId) {
        return updateDraftPost(activeDraftId, {
          ...payload,
          ...(activeDraftUpdatedAt ? { expected_updated_at: activeDraftUpdatedAt } : {}),
        });
      }
      return createDraftPost(payload);
    },
    onSuccess: (draft, variables) => {
      queryClient.invalidateQueries({ queryKey: ["feed-drafts"] });
      setActiveDraftId(draft.draft_id);
      setActiveDraftUpdatedAt(draft.updated_at ?? null);
      setActiveDraftBaseline(composerSnapshot);
      setLastSavedSnapshot(composerSnapshot);
      reportDraftLifecycleEvent("save_success", "success");
      if (variables.mode === "manual") toast.success("Draft saved");
      if (variables.mode === "autosave") setAutosaveStatus("saved");
    },
    onError: (err: unknown, variables) => {
      reportDraftLifecycleEvent("save_fail", "fail", telemetryReasonCodeFromError(err));
      if (err instanceof ApiError && err.status === 409) {
        queryClient.invalidateQueries({ queryKey: ["feed-drafts"] });
        if (variables.mode === "autosave") {
          setAutosaveStatus("conflict");
          return;
        }
        setAutosaveStatus("failed");
        const staleDraftId = activeDraftId;
        if (staleDraftId) {
          toast.error("Draft changed on another session. Reloading latest draft...");
          void getDraftPost(staleDraftId)
            .then((freshDraft) => hydrateFromDraft(freshDraft))
            .then(() => {
              toast.success("Latest draft loaded. Review changes and save again.");
            })
            .catch(() => {
              toast.error("Could not reload latest draft. Please load it manually from Saved drafts.");
            });
          return;
        }
        toast.error("Draft changed on another session. Reload latest draft before saving again.");
        return;
      }
      if (variables.mode === "autosave") return;
      const msg = err instanceof Error ? err.message : "Failed to save draft";
      toast.error(msg);
    },
  });

  const loadDraftMutation = useMutation({
    mutationFn: (draftId: string) => getDraftPost(draftId),
    onSuccess: async (draft) => {
      await hydrateFromDraft(draft);
      reportDraftLifecycleEvent("load_success", "success");
      toast.success("Draft loaded");
    },
    onError: (err: unknown) => {
      reportDraftLifecycleEvent("load_fail", "fail", telemetryReasonCodeFromError(err));
      const msg = err instanceof Error ? err.message : "Failed to load draft";
      toast.error(msg);
    },
  });

  const deleteDraftMutation = useMutation({
    mutationFn: ({ draftId, expectedUpdatedAt }: { draftId: string; expectedUpdatedAt?: string }) =>
      deleteDraftPost(draftId, expectedUpdatedAt),
    onSuccess: (_resp, variables) => {
      const draftId = variables.draftId;
      queryClient.setQueryData<{ items: DraftPost[]; next_cursor?: string } | undefined>(["feed-drafts"], (prev) => {
        if (!prev) return prev;
        return { ...prev, items: prev.items.filter((d) => d.draft_id !== draftId) };
      });
      if (activeDraftId === draftId) {
        setActiveDraftId(null);
        setActiveDraftUpdatedAt(null);
        setActiveDraftBaseline(null);
        setLastSavedSnapshot(null);
      }
      reportDraftLifecycleEvent("delete_success", "success");
      toast.success("Draft removed");
    },
    onError: (err: unknown) => {
      reportDraftLifecycleEvent("delete_fail", "fail", telemetryReasonCodeFromError(err));
      if (err instanceof ApiError && err.status === 409) {
        queryClient.invalidateQueries({ queryKey: ["feed-drafts"] });
        toast.error("Draft changed on another session. Refresh and try removing it again.");
        return;
      }
      const msg = err instanceof Error ? err.message : "Failed to remove draft";
      toast.error(msg);
    },
  });

  const activeDraftSummary = useMemo(() => {
    if (body.trim()) return body.trim().slice(0, 60);
    if (imageUrls.length > 0) return `${imageUrls.length} image${imageUrls.length > 1 ? "s" : ""}`;
    if (pendingFiles.length > 0) return `${pendingFiles.length} file${pendingFiles.length > 1 ? "s" : ""}`;
    return "Untitled draft";
  }, [body, imageUrls.length, pendingFiles.length]);

  const canSaveDraft = Boolean(body.trim() || imageUrls.length || pendingFiles.length);
  const hasDraftContentChanges = Boolean(canSaveDraft && composerSnapshot !== lastSavedSnapshot);
  const isEditingLoadedDraft = Boolean(activeDraftId);
  const hasUnsavedDraftChanges = Boolean(
    activeDraftId
      && activeDraftBaseline
      && activeDraftBaseline !== composerSnapshot,
  );

  const isTransientDraftError = (err: unknown) => {
    const msg = err instanceof Error ? err.message.toLowerCase() : "";
    return msg.includes("network") || msg.includes("timeout") || msg.includes("tempor") || msg.includes("429") || msg.includes("5");
  };

  const clearAutosaveTimers = () => {
    if (autosaveDebounceRef.current !== null) {
      window.clearTimeout(autosaveDebounceRef.current);
      autosaveDebounceRef.current = null;
    }
    if (autosaveRetryRef.current !== null) {
      window.clearTimeout(autosaveRetryRef.current);
      autosaveRetryRef.current = null;
    }
  };

  const runAutosaveAttempt = (attempt: number) => {
    if (!isOnline || !hasDraftContentChanges || saveDraftMutation.isPending) return;
    setAutosaveStatus("saving");
    saveDraftMutation.mutate(
      { mode: "autosave" },
      {
        onError: (err) => {
          if (attempt < AUTOSAVE_MAX_RETRIES && isTransientDraftError(err)) {
            const backoffMs = AUTOSAVE_RETRY_BASE_MS * 2 ** attempt;
            setAutosaveStatus("retrying");
            autosaveRetryRef.current = window.setTimeout(() => {
              runAutosaveAttempt(attempt + 1);
            }, backoffMs);
            return;
          }
          setAutosaveStatus("failed");
        },
      },
    );
  };

  useEffect(() => {
    return () => clearAutosaveTimers();
  }, []);

  useEffect(() => {
    if (!draftsFeatureEnabled || legacyMigrationRan || !isOnline || draftsQuery.isLoading) return;
    setLegacyMigrationRan(true);

    if (typeof window === "undefined" || typeof window.localStorage === "undefined") return;
    if (window.localStorage.getItem(LEGACY_DRAFT_MIGRATION_FLAG) === "1") return;

    const keys = new Set<string>(LEGACY_DRAFT_KEYS);
    for (let i = 0; i < window.localStorage.length; i += 1) {
      const key = window.localStorage.key(i);
      if (!key) continue;
      if (key.includes("newsfeed") && key.includes("draft")) keys.add(key);
    }

    const importFromLegacy = async () => {
      const parsedByKey: Array<{ key: string; drafts: CreateDraftPostReq[] }> = [];
      for (const key of keys) {
        const raw = window.localStorage.getItem(key);
        if (!raw) continue;
        const parsedDrafts = parseLegacyDraftValue(raw);
        if (parsedDrafts.length > 0) parsedByKey.push({ key, drafts: parsedDrafts });
      }

      if (parsedByKey.length === 0) {
        window.localStorage.setItem(LEGACY_DRAFT_MIGRATION_FLAG, "1");
        return;
      }

      let importedCount = 0;
      let failedCount = 0;
      for (const entry of parsedByKey) {
        let keyHasFailure = false;
        for (const draft of entry.drafts) {
          try {
            await createDraftPost(draft);
            importedCount += 1;
          } catch {
            keyHasFailure = true;
            failedCount += 1;
          }
        }
        if (!keyHasFailure) window.localStorage.removeItem(entry.key);
      }

      if (importedCount > 0) {
        queryClient.invalidateQueries({ queryKey: ["feed-drafts"] });
        toast.success(`Imported ${importedCount} local draft${importedCount > 1 ? "s" : ""} from this device`);
      }
      if (failedCount > 0) {
        toast.info(`${failedCount} local draft${failedCount > 1 ? "s" : ""} could not be imported`);
        return;
      }
      window.localStorage.setItem(LEGACY_DRAFT_MIGRATION_FLAG, "1");
    };

    void importFromLegacy();
  }, [draftsFeatureEnabled, legacyMigrationRan, isOnline, draftsQuery.isLoading, queryClient]);

  useEffect(() => {
    if (!draftsFeatureEnabled) return;
    if (!isOnline) {
      clearAutosaveTimers();
      if (canSaveDraft) setAutosaveStatus("offline");
      return;
    }
    if (autosaveStatus === "conflict") {
      clearAutosaveTimers();
      return;
    }
    if (!canSaveDraft || !hasDraftContentChanges || saveDraftMutation.isPending) {
      if (!canSaveDraft) setAutosaveStatus("idle");
      return;
    }

    clearAutosaveTimers();
    autosaveDebounceRef.current = window.setTimeout(() => {
      runAutosaveAttempt(0);
    }, AUTOSAVE_DEBOUNCE_MS);
  }, [draftsFeatureEnabled, isOnline, canSaveDraft, hasDraftContentChanges, composerSnapshot, saveDraftMutation.isPending, autosaveStatus]);

  const handleSaveDraft = () => {
    if (!draftsFeatureEnabled) {
      toast.info("Drafts are currently unavailable");
      return;
    }
    if (!canSaveDraft) {
      toast.error("Add content before saving a draft");
      return;
    }
    if (!isOnline) {
      toast.error("Draft sync requires an internet connection");
      return;
    }
    saveDraftMutation.mutate({ mode: "manual" });
  };

  const handleLoadDraftSelection = (draftId: string) => {
    if (activeDraftId && activeDraftId !== draftId && hasUnsavedDraftChanges) {
      const proceed = window.confirm("You have unsaved draft changes. Discard and load another draft?");
      if (!proceed) return;
    }
    loadDraftMutation.mutate(draftId);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (mutation.isPending || saveDraftMutation.isPending) return;
    if (!body.trim() && imageUrls.length === 0 && pendingFiles.length === 0) return;
    if (!validateUnlockControls()) return;

    if (!isOnline) {
      const queuedPayload = {
        ...buildContentPayload(body, editorMode, richDoc),
        ...(imageUrls.length > 0 ? { image_urls: imageUrls } : {}),
        ...(pendingFiles.length > 0 ? { file_paths: pendingFiles.map((f) => f.path) } : {}),
        ...(unlockPriceCents ? { unlock_price_cents: unlockPriceCents } : {}),
        ...(schedulingUiEnabled && scheduledAt
          ? {
              publish_at: Math.floor(scheduledAt.getTime() / 1000),
              schedule_timezone: scheduleTimezone,
              scheduled_at_local: scheduledInput || undefined,
            }
          : {}),
        ...(parsedUnlockLimit ? { unlock_limit: parsedUnlockLimit } : {}),
      };
      addToQueue({ type: "create_post", payload: queuedPayload });
      toast.info("You're offline — post queued and will publish when reconnected");
      resetComposer();
      return;
    }

    if (draftsFeatureEnabled && activeDraftId && hasUnsavedDraftChanges) {
      saveDraftMutation.mutate(
        { mode: "pre_publish" },
        {
          onSuccess: (draft) => {
            mutation.mutate({
              draftId: draft.draft_id,
              updatedAt: draft.updated_at ?? undefined,
            });
          },
        },
      );
      return;
    }

    mutation.mutate();
  };

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = "";

    if (!file.type.startsWith("image/")) {
      toast.error("Please select an image file");
      return;
    }

    if (file.size > 10 * 1024 * 1024) {
      toast.error("Image must be under 10 MB");
      return;
    }

    setUploading(true);
    setUploadProgress(50);

    try {
      const result = await uploadPostImage(file);
      setUploadProgress(100);
      setImageUrls((prev) => [...prev, result.url]);
      toast.success("Image uploaded");
    } catch {
      toast.error("Failed to upload image");
    } finally {
      setUploading(false);
      setUploadProgress(0);
    }
  };

  const removeImage = (index: number) => {
    setImageUrls((prev) => prev.filter((_, i) => i !== index));
  };

  const handleFileManagerSelect = async (entry: FileEntry) => {
    if (entry.type === "folder") return;
    const ct = entry.content_type ?? "";
    if (!ct.startsWith("image/")) {
      toast.error("Only image files can be attached to posts");
      return;
    }
    if (imageUrls.length >= MAX_IMAGES) {
      toast.error(`Maximum ${MAX_IMAGES} images per post`);
      return;
    }

    setFilePickerOpen(false);
    setUploading(true);
    setUploadProgress(30);

    try {
      const resp = await fetch(downloadUrl(entry.path), { credentials: "include" });
      if (!resp.ok) throw new Error("Failed to fetch file");
      setUploadProgress(60);
      const blob = await resp.blob();
      const file = new File([blob], entry.name, { type: ct });
      if (file.size > 10 * 1024 * 1024) {
        toast.error("Image must be under 10 MB");
        return;
      }
      const result = await uploadPostImage(file);
      setUploadProgress(100);
      setImageUrls((prev) => [...prev, result.url]);
      toast.success("Image attached from Files");
    } catch {
      toast.error("Failed to attach image from Files");
    } finally {
      setUploading(false);
      setUploadProgress(0);
    }
  };

  const handleAttachFileSelect = (entry: FileEntry) => {
    if (entry.type === "folder") return;
    if (pendingFiles.length >= MAX_FILES) {
      toast.error(`Maximum ${MAX_FILES} file attachments per post`);
      return;
    }
    if (pendingFiles.some((f) => f.path === entry.path)) {
      toast.error("File already attached");
      return;
    }
    setPendingFiles((prev) => [...prev, entry]);
    setAttachFilePickerOpen(false);
  };

  const drafts = draftsQuery.data?.items ?? [];

  return (
    <Card>
      <CardContent className="p-4">
        <form onSubmit={handleSubmit} className="space-y-3">
          <MarkdownComposer
            mode={editorMode}
            onModeChange={setEditorMode}
            value={body}
            onChange={setBody}
            richDoc={richDoc}
            onRichDocChange={setRichDoc}
            placeholder="What's on your mind?"
            rows={3}
          />

          {schedulingUiEnabled && (
            <div className="rounded-md border border-border/60 bg-muted/20 p-2.5">
            <div className="flex items-center justify-between">
              <button
                type="button"
                className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-foreground"
                onClick={() => setScheduleOpen((v) => !v)}
              >
                <Clock className="h-3.5 w-3.5" />
                {scheduledAt ? "Scheduled post" : "Schedule post"}
              </button>
              {scheduledAt && (
                <button
                  type="button"
                  className="text-xs text-muted-foreground underline underline-offset-2 hover:text-foreground"
                  onClick={() => {
                    setScheduledAt(null);
                    setScheduledInput("");
                  }}
                >
                  Remove schedule
                </button>
              )}
            </div>
            {scheduleOpen && (
              <div className="mt-2 space-y-2">
                <input
                  type="datetime-local"
                  value={scheduledInput}
                  className="w-full rounded border border-input bg-background px-2 py-1.5 text-xs"
                  onChange={(e) => {
                    const val = e.target.value;
                    setScheduledInput(val);
                    if (val) {
                      setScheduledAt(parseDateTimeInTz(val, scheduleTimezone));
                    } else {
                      setScheduledAt(null);
                    }
                  }}
                />
                <div className="flex items-center gap-1.5">
                  <Globe className="h-3.5 w-3.5 text-muted-foreground" />
                  <input
                    type="text"
                    value={scheduleTimezone}
                    onChange={(e) => {
                      const tz = e.target.value;
                      setScheduleTimezone(tz);
                      if (scheduledInput) setScheduledAt(parseDateTimeInTz(scheduledInput, tz));
                    }}
                    className="w-full rounded border border-input bg-background px-2 py-1.5 text-xs"
                    placeholder="Timezone (e.g. America/New_York)"
                  />
                </div>
              </div>
            )}
            {scheduledAt && (
              <p className="mt-2 text-[11px] text-muted-foreground">
                Publishes: {scheduledAt.toLocaleString(undefined, { timeZoneName: "short" })}
              </p>
            )}
            </div>
          )}

          {/* Upload progress */}
          {uploading && (
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Loader2 className="h-3 w-3 animate-spin" />
                Uploading image...
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
                <div className="h-full rounded-full bg-primary transition-all duration-300" style={{ width: `${uploadProgress}%` }} />
              </div>
            </div>
          )}

          {imageUrls.length > 0 && !uploading && (
            <div className="flex flex-wrap gap-2">
              {imageUrls.map((url, i) => (
                <div key={i} className="relative inline-block">
                  <img src={url} alt={`Attachment ${i + 1}`} className="h-24 w-24 rounded-lg object-cover" />
                  <button
                    type="button"
                    onClick={() => removeImage(i)}
                    className="absolute -right-1.5 -top-1.5 flex h-5 w-5 items-center justify-center rounded-full bg-destructive text-destructive-foreground shadow-sm"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </div>
              ))}
            </div>
          )}

          {pendingFiles.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {pendingFiles.map((f, i) => (
                <div key={f.path} className="flex items-center gap-1 rounded-full border bg-muted/50 px-2.5 py-1 text-xs">
                  <Paperclip className="h-3 w-3 text-muted-foreground shrink-0" />
                  <span className="max-w-[140px] truncate">{f.name}</span>
                  <button
                    type="button"
                    onClick={() => setPendingFiles((prev) => prev.filter((_, idx) => idx !== i))}
                    className="ml-0.5 text-muted-foreground hover:text-destructive"
                    aria-label={`Remove ${f.name}`}
                  >
                    <X className="h-3 w-3" />
                  </button>
                </div>
              ))}
            </div>
          )}

          {lockEnabled && (
            <div className="rounded-md border border-border bg-muted/30 p-2 text-xs space-y-1.5">
              <div className="flex items-center gap-2">
                <label className="text-muted-foreground shrink-0">Lock price ($)</label>
                <input
                  type="number"
                  min="0.01"
                  step="0.01"
                  value={lockPrice}
                  onChange={(e) => setLockPrice(e.target.value)}
                  placeholder="e.g. 2.99"
                  className="flex-1 rounded border border-input bg-background px-2 py-1 text-xs"
                />
              </div>
              <p className="text-muted-foreground">Viewers must pay this amount to unlock the post.</p>
              {unlockLimitFeatureEnabled && (
                <>
                  <div className="flex items-center gap-2">
                    <input
                      id="unlock-limit-enabled-create"
                      type="checkbox"
                      checked={unlockLimitEnabled}
                      onChange={(e) => {
                        const checked = e.target.checked;
                        setUnlockLimitEnabled(checked);
                        if (!checked) {
                          setUnlockLimit("");
                          setUnlockLimitError(null);
                        }
                      }}
                    />
                    <label htmlFor="unlock-limit-enabled-create" className="text-muted-foreground">
                      Limit unlocks to N users
                    </label>
                  </div>
                  {unlockLimitEnabled && (
                    <div className="space-y-1">
                      <input
                        type="number"
                        min={1}
                        step={1}
                        value={unlockLimit}
                        onChange={(e) => {
                          setUnlockLimit(e.target.value);
                          if (unlockLimitError) setUnlockLimitError(null);
                        }}
                        placeholder="e.g. 50"
                        className="w-full rounded border border-input bg-background px-2 py-1 text-xs"
                      />
                      {unlockLimitError && (
                        <p className="text-[11px] text-destructive">{unlockLimitError}</p>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-y-1">
            <div className="flex flex-wrap items-center gap-1">
              {draftsFeatureEnabled && (
                <Button type="button" variant="ghost" size="sm" onClick={handleSaveDraft} disabled={(!canSaveDraft && !hasUnsavedDraftChanges) || saveDraftMutation.isPending || uploading}>
                  {isEditingLoadedDraft ? (hasUnsavedDraftChanges ? "Save changes" : "Saved") : "Save Draft"}
                </Button>
              )}

              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => fileRef.current?.click()}
                disabled={uploading || imageUrls.length >= MAX_IMAGES}
              >
                <ImagePlus className="mr-1 h-3.5 w-3.5" />
                Photo
                {imageUrls.length > 0 && <span className="ml-1 text-xs text-muted-foreground">({imageUrls.length}/{MAX_IMAGES})</span>}
              </Button>

              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setFilePickerOpen(true)}
                disabled={uploading || imageUrls.length >= MAX_IMAGES}
              >
                <FolderOpen className="mr-1 h-3.5 w-3.5" />
                From Files
              </Button>

              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setAttachFilePickerOpen(true)}
                disabled={uploading || pendingFiles.length >= MAX_FILES}
              >
                <Paperclip className="mr-1 h-3.5 w-3.5" />
                Attach File
                {pendingFiles.length > 0 && <span className="ml-1 text-xs text-muted-foreground">({pendingFiles.length}/{MAX_FILES})</span>}
              </Button>

              {/* Lock toggle */}
              <Button
                type="button"
                variant={lockEnabled ? "secondary" : "ghost"}
                size="sm"
                onClick={() =>
                  setLockEnabled((v) => {
                    const next = !v;
                    if (!next) {
                      setLockPrice("");
                      setUnlockLimitEnabled(false);
                      setUnlockLimit("");
                      setUnlockLimitError(null);
                    }
                    return next;
                  })
                }
                disabled={mutation.isPending}
              >
                <Lock className="mr-1 h-3.5 w-3.5" />
                {lockEnabled ? `Lock · $${lockPrice || "0"}` : "Lock"}
              </Button>
            </div>

            <input ref={fileRef} type="file" accept="image/*" className="hidden" onChange={handleFileSelect} />

            <Button
              type="submit"
              size="sm"
              disabled={(!body.trim() && imageUrls.length === 0 && pendingFiles.length === 0) || mutation.isPending || saveDraftMutation.isPending || uploading}
            >
              <Send className="mr-1 h-3.5 w-3.5" />
              {(mutation.isPending || saveDraftMutation.isPending) ? "Posting..." : "Post"}
            </Button>
          </div>

          {draftsFeatureEnabled && (
            <div className="rounded-md border border-border/70 bg-muted/30 p-2 space-y-1.5">
              <div className="text-xs font-medium">Saved drafts ({drafts.length})</div>

            {draftsQuery.isLoading ? (
              <div className="space-y-1">
                <div className="h-8 rounded bg-muted animate-pulse" />
                <div className="h-8 rounded bg-muted animate-pulse" />
              </div>
            ) : draftsQuery.isError ? (
              <div className="flex items-center justify-between gap-2 rounded border border-destructive/30 bg-destructive/5 px-2 py-1.5">
                <p className="text-xs text-destructive">Could not load drafts</p>
                <Button type="button" variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={() => draftsQuery.refetch()}>
                  Retry
                </Button>
              </div>
            ) : drafts.length === 0 ? (
              <p className="text-xs text-muted-foreground">No saved drafts yet.</p>
            ) : (
              <div className="space-y-1">
                {drafts.map((draft) => (
                  <div key={draft.draft_id} className="flex items-center justify-between gap-2 rounded border bg-background px-2 py-1.5">
                    <div className="min-w-0">
                      <p className="truncate text-xs font-medium">{(draft.body_plain ?? draft.body ?? "Untitled draft").trim().slice(0, 80) || "Untitled draft"}</p>
                      <p className="text-[11px] text-muted-foreground">
                        {new Date(draft.updated_at ?? draft.created_at).toLocaleString()} · {draft.body_format ?? "plain"}
                      </p>
                    </div>
                    <div className="flex items-center gap-1">
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        className="h-7 px-2 text-xs"
                        onClick={() => handleLoadDraftSelection(draft.draft_id)}
                        disabled={loadDraftMutation.isPending}
                      >
                        Load
                      </Button>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2 text-xs text-destructive hover:text-destructive"
                        onClick={() =>
                          deleteDraftMutation.mutate({
                            draftId: draft.draft_id,
                            expectedUpdatedAt: activeDraftId === draft.draft_id
                              ? (activeDraftUpdatedAt ?? draft.updated_at)
                              : draft.updated_at,
                          })}
                        disabled={deleteDraftMutation.isPending}
                      >
                        Remove
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}

              {canSaveDraft && <p className="text-[11px] text-muted-foreground">Ready to save: {activeDraftSummary}</p>}
              {isEditingLoadedDraft && (
                <p className="text-[11px] text-muted-foreground">
                  Draft state: {hasUnsavedDraftChanges ? "Unsaved changes" : "All changes saved"}
                </p>
              )}
              {canSaveDraft && autosaveStatus === "saving" && <p className="text-[11px] text-muted-foreground">Autosaving draft…</p>}
              {canSaveDraft && autosaveStatus === "retrying" && <p className="text-[11px] text-muted-foreground">Autosave retrying…</p>}
              {canSaveDraft && autosaveStatus === "saved" && <p className="text-[11px] text-muted-foreground">Saved just now</p>}
              {canSaveDraft && autosaveStatus === "failed" && <p className="text-[11px] text-destructive">Autosave failed. Please save manually.</p>}
              {canSaveDraft && autosaveStatus === "offline" && <p className="text-[11px] text-muted-foreground">Autosave paused while offline</p>}
              {canSaveDraft && autosaveStatus === "conflict" && (
                <div className="flex items-center justify-between gap-2">
                  <p className="text-[11px] text-destructive">Autosave paused: draft changed on another session.</p>
                  {activeDraftId && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="h-6 px-2 text-[11px]"
                      onClick={() => loadDraftMutation.mutate(activeDraftId)}
                      disabled={loadDraftMutation.isPending}
                    >
                      Reload latest
                    </Button>
                  )}
                </div>
              )}
            </div>
          )}

          <FilePickerDialog
            open={filePickerOpen}
            onClose={() => setFilePickerOpen(false)}
            onSelect={(entry) => void handleFileManagerSelect(entry)}
            showPermission={false}
          />

          <FilePickerDialog
            open={attachFilePickerOpen}
            onClose={() => setAttachFilePickerOpen(false)}
            onSelect={handleAttachFileSelect}
            showPermission={false}
          />
        </form>
      </CardContent>
    </Card>
  );
}
