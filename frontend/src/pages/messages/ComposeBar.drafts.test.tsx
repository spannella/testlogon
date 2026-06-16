import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ComposeBar } from "./ComposeBar";

const toastMock = vi.hoisted(() => ({
  success: vi.fn(),
  error: vi.fn(),
}));

const draftsByConversation = vi.hoisted<Record<string, Array<{ id: string; text: string; saved_at: number }>>>(() => ({
  "conv-a": [
    { id: "d-a1", text: "draft from A", saved_at: 2 },
    { id: "d-a0", text: "older A", saved_at: 1 },
  ],
  "conv-b": [
    { id: "d-b1", text: "draft from B", saved_at: 3 },
  ],
}));

const hookSpy = vi.hoisted(() => ({
  saveDraft: vi.fn(() => true),
  saveExistingDraft: vi.fn(() => true),
  loadDraft: vi.fn(async (draftId: string) => {
    const all = Object.values(draftsByConversation).flat();
    return all.find((d) => d.id === draftId)?.text ?? null;
  }),
  deleteDraft: vi.fn(),
  refresh: vi.fn(async () => {}),
  clearSyncIssue: vi.fn(),
}));

const hookState = vi.hoisted(() => ({
  syncIssue: "none" as "none" | "auth" | "network" | "server",
  requiresReauth: false,
}));

vi.mock("sonner", () => ({
  toast: toastMock,
}));

vi.mock("@/api/endpoints/billing", () => ({
  getPaymentMethods: vi.fn(async () => []),
}));

vi.mock("./useConversationDrafts", () => ({
  useConversationDrafts: vi.fn((conversationId: string) => ({
    drafts: draftsByConversation[conversationId] ?? [],
    saveDraft: hookSpy.saveDraft,
    saveExistingDraft: hookSpy.saveExistingDraft,
    loadDraft: hookSpy.loadDraft,
    deleteDraft: hookSpy.deleteDraft,
    refresh: hookSpy.refresh,
    syncIssue: hookState.syncIssue,
    requiresReauth: hookState.requiresReauth,
    clearSyncIssue: hookSpy.clearSyncIssue,
  })),
}));

function renderWithClient(ui: JSX.Element) {
  const queryClient = new QueryClient();
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
}

describe("ComposeBar draft integration", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    hookState.syncIssue = "none";
    hookState.requiresReauth = false;
    vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => {
      cb(0);
      return 0;
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders saved drafts and wires load/remove controls", async () => {
    const onSendText = vi.fn();
    renderWithClient(<ComposeBar conversationId="conv-a" onSendText={onSendText} />);

    expect(screen.getByText("Saved drafts")).toBeInTheDocument();
    expect(screen.getByText("draft from A")).toBeInTheDocument();

    await userEvent.click(screen.getAllByRole("button", { name: "Load" })[0]);
    expect(hookSpy.loadDraft).toHaveBeenCalledWith("d-a1");
    await waitFor(() => {
      expect(toastMock.success).toHaveBeenCalledWith("Draft loaded");
    });

    await userEvent.click(screen.getAllByRole("button", { name: "Remove" })[0]);
    expect(hookSpy.deleteDraft).toHaveBeenCalledWith("d-a1");
    expect(toastMock.success).toHaveBeenCalledWith("Draft removed");
  });

  it("save draft uses current composer text and gives optimistic feedback", async () => {
    renderWithClient(<ComposeBar conversationId="conv-a" onSendText={vi.fn()} />);

    await userEvent.type(screen.getByPlaceholderText(/Type a message/i), "new draft text");
    expect(screen.getByText("Unsaved draft")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /More compose options/i }));
    await userEvent.click(screen.getByRole("button", { name: /Save draft/i }));

    expect(hookSpy.saveDraft).toHaveBeenCalledWith("new draft text");
    expect(toastMock.success).toHaveBeenCalledWith("Draft saved");
    expect(screen.getByText("Draft saved")).toBeInTheDocument();
  });

  it("save draft updates loaded draft instead of creating a new one", async () => {
    renderWithClient(<ComposeBar conversationId="conv-a" onSendText={vi.fn()} />);

    await userEvent.click(screen.getAllByRole("button", { name: "Load" })[0]);
    await waitFor(() => {
      expect(screen.getByPlaceholderText(/Type a message/i)).toHaveValue("draft from A");
    });
    await userEvent.type(screen.getByPlaceholderText(/Type a message/i), " updated");
    await userEvent.click(screen.getByRole("button", { name: /More compose options/i }));
    await userEvent.click(screen.getByRole("button", { name: /Save draft/i }));

    expect(hookSpy.saveExistingDraft).toHaveBeenCalledWith("d-a1", "draft from A updated");
  });

  it("shows error toast when trying to save an empty draft", async () => {
    hookSpy.saveDraft.mockReturnValueOnce(false);
    renderWithClient(<ComposeBar conversationId="conv-a" onSendText={vi.fn()} />);

    await userEvent.click(screen.getByRole("button", { name: /More compose options/i }));
    await userEvent.click(screen.getByRole("button", { name: /Save draft/i }));

    expect(hookSpy.saveDraft).toHaveBeenCalledWith("");
    expect(toastMock.error).toHaveBeenCalledWith("Type a message before saving a draft");
  });

  it("loading a draft keeps normal send flow intact", async () => {
    const onSendText = vi.fn();
    renderWithClient(<ComposeBar conversationId="conv-a" onSendText={onSendText} />);

    await userEvent.click(screen.getAllByRole("button", { name: "Load" })[0]);
    await userEvent.click(screen.getByLabelText(/Send message/i));

    await waitFor(() => {
      expect(onSendText).toHaveBeenCalledWith(expect.objectContaining({ text: "draft from A" }));
    });
  });

  it("load replaces composer text, restores focus, and supports keyboard send", async () => {
    const onSendText = vi.fn();
    renderWithClient(<ComposeBar conversationId="conv-a" onSendText={onSendText} />);

    const composer = screen.getByPlaceholderText(/Type a message/i);
    await userEvent.type(composer, "temporary text");
    expect(composer).toHaveValue("temporary text");

    await userEvent.click(screen.getAllByRole("button", { name: "Load" })[0]);

    await waitFor(() => {
      expect(composer).toHaveValue("draft from A");
    });
    await waitFor(() => {
      expect(document.activeElement).toBe(composer);
    });

    await userEvent.type(composer, "{enter}");
    await waitFor(() => {
      expect(onSendText).toHaveBeenCalledWith(expect.objectContaining({ text: "draft from A" }));
    });
  });

  it("updates draft list when conversation id changes", () => {
    const queryClient = new QueryClient();
    const { rerender } = render(
      <QueryClientProvider client={queryClient}>
        <ComposeBar conversationId="conv-a" onSendText={vi.fn()} />
      </QueryClientProvider>,
    );

    expect(screen.getByText("draft from A")).toBeInTheDocument();

    rerender(
      <QueryClientProvider client={queryClient}>
        <ComposeBar conversationId="conv-b" onSendText={vi.fn()} />
      </QueryClientProvider>,
    );

    expect(screen.queryByText("draft from A")).not.toBeInTheDocument();
    expect(screen.getByText("draft from B")).toBeInTheDocument();
  });

  it("shows error toast when loading an unavailable draft", async () => {
    hookSpy.loadDraft.mockResolvedValueOnce(null);
    renderWithClient(<ComposeBar conversationId="conv-a" onSendText={vi.fn()} />);

    await userEvent.click(screen.getAllByRole("button", { name: "Load" })[0]);

    expect(toastMock.error).toHaveBeenCalledWith("Draft unavailable");
  });

  it("requires a non-empty conversation id", () => {
    const queryClient = new QueryClient();
    expect(() => render(
      <QueryClientProvider client={queryClient}>
        <ComposeBar conversationId="   " onSendText={vi.fn()} />
      </QueryClientProvider>,
    )).toThrow("ComposeBar requires a non-empty conversationId");
  });

  it("shows network sync recovery with retry and dismiss controls", async () => {
    hookState.syncIssue = "network";
    renderWithClient(<ComposeBar conversationId="conv-a" onSendText={vi.fn()} />);

    expect(screen.getByText("Draft sync issue")).toBeInTheDocument();
    expect(screen.getByText(/offline or the drafts service is unavailable/i)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /Retry sync/i }));
    expect(hookSpy.refresh).toHaveBeenCalledTimes(1);
    expect(toastMock.success).toHaveBeenCalledWith("Draft sync retried");

    await userEvent.click(screen.getByRole("button", { name: /Dismiss/i }));
    expect(hookSpy.clearSyncIssue).toHaveBeenCalledTimes(1);
  });

  it("shows re-auth message without retry button for auth sync issues", () => {
    hookState.syncIssue = "auth";
    hookState.requiresReauth = true;
    renderWithClient(<ComposeBar conversationId="conv-a" onSendText={vi.fn()} />);

    expect(screen.getByText("Draft sync issue")).toBeInTheDocument();
    expect(screen.getByText(/sign in again to sync drafts/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Retry sync/i })).not.toBeInTheDocument();
  });

  it("auto-saves unsent composer text on unmount", async () => {
    const queryClient = new QueryClient();
    const { unmount } = render(
      <QueryClientProvider client={queryClient}>
        <ComposeBar conversationId="conv-a" onSendText={vi.fn()} />
      </QueryClientProvider>,
    );

    const composer = screen.getByPlaceholderText(/Type a message/i);
    await userEvent.type(composer, "persist me");

    unmount();
    expect(hookSpy.saveDraft).toHaveBeenCalledWith("persist me");
  });

  it("shows no draft changes state when composer is empty", () => {
    renderWithClient(<ComposeBar conversationId="conv-a" onSendText={vi.fn()} />);
    expect(screen.getByText("No draft changes")).toBeInTheDocument();
  });

  it("registers beforeunload protection when there are unsaved draft changes", async () => {
    renderWithClient(<ComposeBar conversationId="conv-a" onSendText={vi.fn()} />);
    await userEvent.type(screen.getByPlaceholderText(/Type a message/i), "unsaved");

    const event = new Event("beforeunload", { cancelable: true });
    const dispatched = window.dispatchEvent(event);
    expect(dispatched).toBe(false);
    expect(event.defaultPrevented).toBe(true);
  });

  it("does not block beforeunload when draft state is clean", () => {
    renderWithClient(<ComposeBar conversationId="conv-a" onSendText={vi.fn()} />);

    const event = new Event("beforeunload", { cancelable: true });
    const dispatched = window.dispatchEvent(event);
    expect(dispatched).toBe(true);
    expect(event.defaultPrevented).toBe(false);
  });

  it("autosaves edits for an active draft after idle delay", async () => {
    vi.useFakeTimers();
    renderWithClient(<ComposeBar conversationId="conv-a" onSendText={vi.fn()} />);

    await userEvent.click(screen.getAllByRole("button", { name: "Load" })[0]);
    await waitFor(() => {
      expect(screen.getByPlaceholderText(/Type a message/i)).toHaveValue("draft from A");
    });

    const composer = screen.getByPlaceholderText(/Type a message/i);
    fireEvent.change(composer, { target: { value: "draft from A autosaved" } });
    expect(screen.getByText("Unsaved draft")).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(1300);
    });

    expect(hookSpy.saveExistingDraft).toHaveBeenCalledWith("d-a1", "draft from A autosaved");
    expect(screen.getByText("Draft saved")).toBeInTheDocument();
    vi.useRealTimers();
  });

  it("debounces active-draft autosave and persists only latest typed value", async () => {
    vi.useFakeTimers();
    renderWithClient(<ComposeBar conversationId="conv-a" onSendText={vi.fn()} />);

    await userEvent.click(screen.getAllByRole("button", { name: "Load" })[0]);
    await waitFor(() => {
      expect(screen.getByPlaceholderText(/Type a message/i)).toHaveValue("draft from A");
    });

    const composer = screen.getByPlaceholderText(/Type a message/i);
    fireEvent.change(composer, { target: { value: "draft from A v1" } });
    act(() => {
      vi.advanceTimersByTime(700);
    });
    fireEvent.change(composer, { target: { value: "draft from A v2" } });
    act(() => {
      vi.advanceTimersByTime(700);
    });

    expect(hookSpy.saveExistingDraft).not.toHaveBeenCalledWith("d-a1", "draft from A v1");

    act(() => {
      vi.advanceTimersByTime(600);
    });

    expect(hookSpy.saveExistingDraft).toHaveBeenCalledTimes(1);
    expect(hookSpy.saveExistingDraft).toHaveBeenCalledWith("d-a1", "draft from A v2");
    vi.useRealTimers();
  });

  it("autosaves new unsaved composer text via saveDraft after idle delay", () => {
    vi.useFakeTimers();
    renderWithClient(<ComposeBar conversationId="conv-c" onSendText={vi.fn()} />);

    const composer = screen.getByPlaceholderText(/Type a message/i);
    fireEvent.change(composer, { target: { value: "new autosaved draft" } });

    act(() => {
      vi.advanceTimersByTime(1300);
    });

    expect(hookSpy.saveDraft).toHaveBeenCalledWith("new autosaved draft");
    expect(screen.getByText("Draft saved")).toBeInTheDocument();
    vi.useRealTimers();
  });

  it("does not autosave when value matches already persisted draft text", async () => {
    vi.useFakeTimers();
    renderWithClient(<ComposeBar conversationId="conv-a" onSendText={vi.fn()} />);

    await userEvent.click(screen.getAllByRole("button", { name: "Load" })[0]);
    await waitFor(() => {
      expect(screen.getByPlaceholderText(/Type a message/i)).toHaveValue("draft from A");
    });

    const composer = screen.getByPlaceholderText(/Type a message/i);
    fireEvent.change(composer, { target: { value: "draft from A" } });
    act(() => {
      vi.advanceTimersByTime(1300);
    });

    expect(hookSpy.saveExistingDraft).not.toHaveBeenCalledWith("d-a1", "draft from A");
    vi.useRealTimers();
  });

  it("flushes dirty draft to storage when tab becomes hidden", () => {
    renderWithClient(<ComposeBar conversationId="conv-c" onSendText={vi.fn()} />);
    const composer = screen.getByPlaceholderText(/Type a message/i);
    fireEvent.change(composer, { target: { value: "hidden flush draft" } });

    const original = Object.getOwnPropertyDescriptor(document, "visibilityState");
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "hidden",
    });
    document.dispatchEvent(new Event("visibilitychange"));

    expect(hookSpy.saveDraft).toHaveBeenCalledWith("hidden flush draft");
    if (original) {
      Object.defineProperty(document, "visibilityState", original);
    }
  });

  it("does not flush when visibility changes but tab is still visible", () => {
    renderWithClient(<ComposeBar conversationId="conv-c" onSendText={vi.fn()} />);
    const composer = screen.getByPlaceholderText(/Type a message/i);
    fireEvent.change(composer, { target: { value: "stay visible" } });

    const original = Object.getOwnPropertyDescriptor(document, "visibilityState");
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "visible",
    });
    document.dispatchEvent(new Event("visibilitychange"));

    expect(hookSpy.saveDraft).not.toHaveBeenCalledWith("stay visible");
    if (original) {
      Object.defineProperty(document, "visibilityState", original);
    }
  });

  it("does not flush on hidden visibility when composer is sending", () => {
    renderWithClient(<ComposeBar conversationId="conv-c" onSendText={vi.fn()} sending />);
    const composer = screen.getByPlaceholderText(/Type a message/i);
    fireEvent.change(composer, { target: { value: "sending suppresses flush" } });

    const original = Object.getOwnPropertyDescriptor(document, "visibilityState");
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: "hidden",
    });
    document.dispatchEvent(new Event("visibilitychange"));

    expect(hookSpy.saveDraft).not.toHaveBeenCalledWith("sending suppresses flush");
    if (original) {
      Object.defineProperty(document, "visibilityState", original);
    }
  });
});
