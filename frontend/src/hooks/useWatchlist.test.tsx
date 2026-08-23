import { describe, expect, it, beforeEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useWatchlist } from "./useWatchlist";
import { WATCHLIST_KEY } from "@/lib/watchlist";

describe("useWatchlist store binding", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("starts empty and toggling a token adds then removes it", () => {
    const { result } = renderHook(() => useWatchlist());
    expect(result.current.items).toHaveLength(0);
    expect(result.current.has("token", "t1")).toBe(false);

    act(() => result.current.toggle("token", "t1"));
    expect(result.current.has("token", "t1")).toBe(true);
    expect(result.current.items).toEqual([{ kind: "token", id: "t1" }]);

    act(() => result.current.toggle("token", "t1"));
    expect(result.current.has("token", "t1")).toBe(false);
    expect(result.current.items).toHaveLength(0);
  });

  it("persists toggles to localStorage under the shared key", () => {
    const { result } = renderHook(() => useWatchlist());
    act(() => result.current.toggle("strategy", "s9"));
    const raw = window.localStorage.getItem(WATCHLIST_KEY);
    expect(raw).toBeTruthy();
    expect(JSON.parse(raw as string)).toEqual([{ kind: "strategy", id: "s9" }]);
  });

  it("remove() deletes a specific instrument", () => {
    const { result } = renderHook(() => useWatchlist());
    act(() => result.current.toggle("token", "t1"));
    act(() => result.current.toggle("strategy", "s2"));
    expect(result.current.items).toHaveLength(2);

    act(() => result.current.remove("token", "t1"));
    expect(result.current.has("token", "t1")).toBe(false);
    expect(result.current.has("strategy", "s2")).toBe(true);
    expect(result.current.items).toEqual([{ kind: "strategy", id: "s2" }]);
  });

  it("two mounted consumers stay in sync via the change event", () => {
    const a = renderHook(() => useWatchlist());
    const b = renderHook(() => useWatchlist());

    act(() => a.result.current.toggle("token", "shared"));
    // The second consumer re-reads on the same-tab WATCHLIST_EVENT.
    expect(b.result.current.has("token", "shared")).toBe(true);
  });

  it("migrates a legacy bare symbol-id array on first read", () => {
    window.localStorage.setItem(WATCHLIST_KEY, JSON.stringify([101, 202]));
    const { result } = renderHook(() => useWatchlist());
    expect(result.current.has("symbol", 101)).toBe(true);
    expect(result.current.has("symbol", "202")).toBe(true);
  });
});
