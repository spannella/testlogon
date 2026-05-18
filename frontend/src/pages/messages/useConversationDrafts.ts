import * as React from "react";

import {
  createConversationDraft,
  deleteConversationDraft as deleteConversationDraftApi,
  getConversationDraft,
  listConversationDrafts,
  updateConversationDraft,
} from "@/api/endpoints/messaging";
import { ApiError } from "@/api/client";
import { emitMessagingDraftEvent } from "@/lib/messagingDraftAnalytics";
import { isMessagingDraftsEnabled } from "@/lib/featureFlags";

export interface ConversationDraft {
  id: string;
  text: string;
  saved_at: number;
}

const MAX_DRAFTS_DEFAULT = 20;
type DraftSyncIssue = "none" | "auth" | "network" | "server";

function classifySyncIssue(err: unknown): DraftSyncIssue {
  if (err instanceof ApiError) {
    if (err.status === 401 || err.status === 403) return "auth";
    if (err.status === 0) return "network";
    return "server";
  }
  if (err instanceof TypeError) {
    return "network";
  }
  return "server";
}

function assertConversationId(conversationId: string): string {
  const normalized = conversationId.trim();
  if (!normalized) {
    throw new Error("useConversationDrafts requires a non-empty conversationId");
  }
  return normalized;
}

function toMillis(timestamp: number | undefined): number {
  if (!timestamp) return 0;
  return timestamp > 1_000_000_000_000 ? timestamp : timestamp * 1000;
}

function normalizeDrafts(value: unknown): ConversationDraft[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is ConversationDraft => (
      !!item
      && typeof item === "object"
      && typeof (item as ConversationDraft).id === "string"
      && typeof (item as ConversationDraft).text === "string"
      && typeof (item as ConversationDraft).saved_at === "number"
    ))
    .sort((a, b) => b.saved_at - a.saved_at);
}

function mergeDrafts(localDrafts: ConversationDraft[], serverDrafts: ConversationDraft[], maxDrafts: number): ConversationDraft[] {
  const byId = new Map<string, ConversationDraft>();
  for (const draft of [...localDrafts, ...serverDrafts]) {
    const existing = byId.get(draft.id);
    if (!existing || draft.saved_at >= existing.saved_at) {
      byId.set(draft.id, draft);
    }
  }
  return [...byId.values()]
    .sort((a, b) => b.saved_at - a.saved_at)
    .slice(0, maxDrafts);
}

function readDrafts(storageKey: string): ConversationDraft[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(storageKey);
    return normalizeDrafts(raw ? JSON.parse(raw) : []);
  } catch {
    return [];
  }
}

function writeDrafts(storageKey: string, drafts: ConversationDraft[]): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(storageKey, JSON.stringify(drafts));
}

export function useConversationDrafts(conversationId: string, maxDrafts = MAX_DRAFTS_DEFAULT) {
  const normalizedConversationId = React.useMemo(
    () => assertConversationId(conversationId),
    [conversationId],
  );
  const storageKey = React.useMemo(() => `messaging:drafts:${normalizedConversationId}`, [normalizedConversationId]);
  const [drafts, setDrafts] = React.useState<ConversationDraft[]>([]);
  const draftsEnabled = isMessagingDraftsEnabled();
  const [syncIssue, setSyncIssue] = React.useState<DraftSyncIssue>("none");

  const refresh = React.useCallback(async () => {
    if (!draftsEnabled) {
      setDrafts([]);
      return;
    }
    const local = readDrafts(storageKey);
    setDrafts(local);

    try {
      const resp = await listConversationDrafts(normalizedConversationId, undefined, maxDrafts * 2);
      const server = (resp.items ?? []).map((draft) => ({
        id: draft.draft_id,
        text: draft.text,
        saved_at: toMillis(draft.updated_at || draft.created_at),
      }));
      const merged = mergeDrafts(local, server, maxDrafts);
      writeDrafts(storageKey, merged);
      setDrafts(merged);
      emitMessagingDraftEvent({
        event: "draft_refresh",
        outcome: "success",
        source: "server",
        conversation_id_present: true,
        at_ms: Date.now(),
      });
      setSyncIssue("none");
    } catch (error) {
      // Offline/unavailable API falls back to local drafts only.
      setSyncIssue(classifySyncIssue(error));
      emitMessagingDraftEvent({
        event: "draft_fallback",
        outcome: "success",
        source: "local",
        reason: "refresh_failed",
        conversation_id_present: true,
        at_ms: Date.now(),
      });
    }
  }, [draftsEnabled, maxDrafts, normalizedConversationId, storageKey]);

  React.useEffect(() => {
    void refresh();
  }, [refresh]);

  React.useEffect(() => {
    if (!draftsEnabled || typeof window === "undefined") return;
    const onOnline = () => {
      void refresh();
    };
    window.addEventListener("online", onOnline);
    return () => {
      window.removeEventListener("online", onOnline);
    };
  }, [draftsEnabled, refresh]);

  React.useEffect(() => {
    if (!draftsEnabled || typeof window === "undefined") return;
    const onStorage = (event: StorageEvent) => {
      if (event.storageArea !== window.localStorage) return;
      if (event.key !== storageKey) return;
      try {
        const next = normalizeDrafts(event.newValue ? JSON.parse(event.newValue) : []);
        setDrafts(next.slice(0, maxDrafts));
      } catch {
        setDrafts([]);
      }
    };
    window.addEventListener("storage", onStorage);
    return () => {
      window.removeEventListener("storage", onStorage);
    };
  }, [draftsEnabled, maxDrafts, storageKey]);

  const saveDraft = React.useCallback((text: string) => {
    if (!draftsEnabled) return false;
    const trimmed = text.trim();
    if (!trimmed) return false;

    const now = Date.now();
    const tempId = `local-${now}`;
    const optimistic = mergeDrafts(
      [
        { id: tempId, text: trimmed, saved_at: now },
        ...readDrafts(storageKey),
      ],
      [],
      maxDrafts,
    );

    writeDrafts(storageKey, optimistic);
    setDrafts(optimistic);
    emitMessagingDraftEvent({
      event: "draft_save",
      outcome: "success",
      source: "local",
      conversation_id_present: true,
      at_ms: Date.now(),
    });

    void (async () => {
      try {
        const created = await createConversationDraft(
          normalizedConversationId,
          { text: trimmed, client_updated_at: now },
          `${normalizedConversationId}:${tempId}`,
        );
        const serverDraft: ConversationDraft = {
          id: created.draft_id,
          text: created.text,
          saved_at: toMillis(created.updated_at || created.created_at),
        };
        const reconciled = mergeDrafts(
          readDrafts(storageKey).filter((draft) => draft.id !== tempId),
          [serverDraft],
          maxDrafts,
        );
        writeDrafts(storageKey, reconciled);
        setDrafts(reconciled);
        emitMessagingDraftEvent({
          event: "draft_save",
          outcome: "success",
          source: "server",
          conversation_id_present: true,
          at_ms: Date.now(),
        });
        setSyncIssue("none");
      } catch (error) {
        // Leave optimistic local draft when API is unavailable.
        setSyncIssue(classifySyncIssue(error));
        emitMessagingDraftEvent({
          event: "draft_fallback",
          outcome: "success",
          source: "local",
          reason: "create_failed",
          conversation_id_present: true,
          at_ms: Date.now(),
        });
      }
    })();

    return true;
  }, [draftsEnabled, maxDrafts, normalizedConversationId, storageKey]);

  const loadDraft = React.useCallback(async (draftId: string) => {
    if (!draftsEnabled) return null;
    const local = drafts.find((draft) => draft.id === draftId)?.text;
    if (local != null) {
      emitMessagingDraftEvent({
        event: "draft_load",
        outcome: "success",
        source: "local",
        conversation_id_present: true,
        at_ms: Date.now(),
      });
      return local;
    }

    try {
      const remote = await getConversationDraft(normalizedConversationId, draftId);
      const serverDraft: ConversationDraft = {
        id: remote.draft_id,
        text: remote.text,
        saved_at: toMillis(remote.updated_at || remote.created_at),
      };
      const reconciled = mergeDrafts(readDrafts(storageKey), [serverDraft], maxDrafts);
      writeDrafts(storageKey, reconciled);
      setDrafts(reconciled);
      emitMessagingDraftEvent({
        event: "draft_load",
        outcome: "success",
        source: "server",
        conversation_id_present: true,
        at_ms: Date.now(),
      });
      setSyncIssue("none");
      return remote.text;
    } catch (error) {
      // Keep null on failures.
      setSyncIssue(classifySyncIssue(error));
      emitMessagingDraftEvent({
        event: "draft_load",
        outcome: "failure",
        source: "server",
        reason: "remote_load_failed",
        conversation_id_present: true,
        at_ms: Date.now(),
      });
      return null;
    }
  }, [drafts, draftsEnabled, maxDrafts, normalizedConversationId, storageKey]);

  const deleteDraft = React.useCallback((draftId: string) => {
    if (!draftsEnabled) return;
    const existing = drafts.find((draft) => draft.id === draftId);
    const next = drafts.filter((draft) => draft.id !== draftId);
    writeDrafts(storageKey, next);
    setDrafts(next);
    emitMessagingDraftEvent({
      event: "draft_remove",
      outcome: "success",
      source: "local",
      conversation_id_present: true,
      at_ms: Date.now(),
    });

    if (!existing || draftId.startsWith("local-")) {
      return;
    }

    void deleteConversationDraftApi(normalizedConversationId, draftId).catch((error) => {
      // Keep local deletion if the API call fails.
      setSyncIssue(classifySyncIssue(error));
      emitMessagingDraftEvent({
        event: "draft_remove",
        outcome: "failure",
        source: "server",
        reason: "delete_failed",
        conversation_id_present: true,
        at_ms: Date.now(),
      });
    });
  }, [drafts, draftsEnabled, normalizedConversationId, storageKey]);

  const saveExistingDraft = React.useCallback((draftId: string, text: string) => {
    if (!draftsEnabled) return false;
    const trimmed = text.trim();
    if (!trimmed) return false;

    const now = Date.now();
    const next = mergeDrafts(
      [
        { id: draftId, text: trimmed, saved_at: now },
        ...drafts.filter((draft) => draft.id !== draftId),
      ],
      [],
      maxDrafts,
    );
    writeDrafts(storageKey, next);
    setDrafts(next);
    emitMessagingDraftEvent({
      event: "draft_update",
      outcome: "success",
      source: "local",
      conversation_id_present: true,
      at_ms: Date.now(),
    });

    if (draftId.startsWith("local-")) {
      return true;
    }

    void updateConversationDraft(normalizedConversationId, draftId, {
      text: trimmed,
      client_updated_at: now,
    }).catch((error) => {
      // Keep local update if the API call fails.
      setSyncIssue(classifySyncIssue(error));
      emitMessagingDraftEvent({
        event: "draft_update",
        outcome: "failure",
        source: "server",
        reason: "update_failed",
        conversation_id_present: true,
        at_ms: Date.now(),
      });
    });

    return true;
  }, [drafts, draftsEnabled, maxDrafts, normalizedConversationId, storageKey]);

  const clearSyncIssue = React.useCallback(() => {
    setSyncIssue("none");
  }, []);

  return {
    drafts,
    saveDraft,
    saveExistingDraft,
    loadDraft,
    deleteDraft,
    refresh,
    syncIssue,
    requiresReauth: syncIssue === "auth",
    clearSyncIssue,
  };
}

export const __private__ = {
  normalizeDrafts,
  mergeDrafts,
  toMillis,
  assertConversationId,
  classifySyncIssue,
};
