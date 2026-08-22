// Persisted store + React hook for CLIENT-SIDE algo orders (TWAP + Iceberg) and
// their Active-Algos monitor. Mirrors the paper-mode / price-alerts store pattern:
// writes persist to localStorage under `algo.orders.v1` and dispatch a same-tab
// event so every mounted `useAlgoOrders()` re-reads; cross-tab sync rides the
// native `storage` event.
//
// IMPORTANT: these algos run ONLY while a tab is open — the actual scheduling /
// child-order placement lives in a runner the ticket mounts (algoRunner.tsx). This
// module is pure state: shape, persistence, and pure reducers (unit-tested-able).

import { useCallback, useEffect, useState } from "react";

export const ALGO_ORDERS_KEY = "algo.orders.v1";

/** Fired (same-tab) whenever the algo store changes. */
export const ALGO_ORDERS_EVENT = "tl:algoOrdersChanged";

export type AlgoKind = "twap" | "iceberg";
export type AlgoStatus = "running" | "paused" | "done" | "cancelled";
export type AlgoSide = "buy" | "sell";

/** A placed child order + its fill state. */
export interface AlgoChild {
  seq: number;
  qty: number;
  /** Scheduled fire time (ms epoch) — TWAP only; iceberg replenishes on fill. */
  atMs?: number;
  status: "pending" | "placed" | "filled";
  /** Fill price (ticks) once known. */
  fillPrice?: number;
  placedAt?: number;
  filledAt?: number;
}

export interface AlgoOrder {
  id: string;
  kind: AlgoKind;
  symbolId: number;
  symbolLabel?: string;
  side: AlgoSide;
  /** Order type each child is placed as. */
  childType: "market" | "limit";
  /** Limit price in ticks (limit children only). */
  limitPrice?: number;
  totalQty: number;
  /** TWAP config. */
  slices?: number;
  durationMs?: number;
  /** Iceberg config. */
  visibleQty?: number;
  /** Whether this algo routes children through the PAPER engine. */
  paper: boolean;
  status: AlgoStatus;
  children: AlgoChild[];
  createdAt: number;
  updatedAt: number;
}

/** Read the persisted algo list (defaults to []). Corrupt values fall back to []. */
export function loadAlgos(): AlgoOrder[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(ALGO_ORDERS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (a): a is AlgoOrder =>
        a &&
        typeof a.id === "string" &&
        (a.kind === "twap" || a.kind === "iceberg") &&
        Array.isArray(a.children),
    );
  } catch {
    return [];
  }
}

/** Persist the list and notify same-tab listeners. */
export function saveAlgos(list: AlgoOrder[]): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(ALGO_ORDERS_KEY, JSON.stringify(list));
  } catch {
    /* quota / private-mode — degrade to no-op */
  }
  try {
    window.dispatchEvent(new Event(ALGO_ORDERS_EVENT));
  } catch {
    /* SSR — no-op */
  }
}

let algoIdCounter = 0;
export function nextAlgoId(): string {
  algoIdCounter += 1;
  return `algo_${Date.now().toString(36)}_${algoIdCounter.toString(36)}`;
}

// ── Pure derived helpers ─────────────────────────────────────────────

/** Ticks filled so far across an algo's children. */
export function filledQty(a: AlgoOrder): number {
  return a.children.reduce((s, c) => s + (c.status === "filled" ? c.qty : 0), 0);
}

/** Count of children fully filled. */
export function slicesDone(a: AlgoOrder): number {
  return a.children.filter((c) => c.status === "filled").length;
}

/** Filled fraction in [0, 1]. */
export function progressFrac(a: AlgoOrder): number {
  if (!(a.totalQty > 0)) return 0;
  return Math.min(1, filledQty(a) / a.totalQty);
}

/** True when every child has filled (TWAP) or the total qty is covered. */
export function isComplete(a: AlgoOrder): boolean {
  return filledQty(a) >= a.totalQty;
}

/** The next child still pending (lowest seq), or undefined. */
export function nextPending(a: AlgoOrder): AlgoChild | undefined {
  return a.children
    .filter((c) => c.status === "pending")
    .sort((x, y) => x.seq - y.seq)[0];
}

// ── React hook ───────────────────────────────────────────────────────

/**
 * React hook exposing the shared algo list plus mutators. Every mutator persists
 * and fans the change out to every other `useAlgoOrders()` consumer + tab.
 */
export function useAlgoOrders() {
  const [algos, setAlgos] = useState<AlgoOrder[]>(() => loadAlgos());

  useEffect(() => {
    const reload = (e?: StorageEvent) => {
      if (e && e.key && e.key !== ALGO_ORDERS_KEY) return;
      setAlgos(loadAlgos());
    };
    window.addEventListener("storage", reload as EventListener);
    window.addEventListener(ALGO_ORDERS_EVENT, reload as EventListener);
    return () => {
      window.removeEventListener("storage", reload as EventListener);
      window.removeEventListener(ALGO_ORDERS_EVENT, reload as EventListener);
    };
  }, []);

  const persist = useCallback((next: AlgoOrder[]) => {
    setAlgos(next);
    saveAlgos(next);
  }, []);

  const add = useCallback(
    (a: AlgoOrder) => persist([a, ...loadAlgos()]),
    [persist],
  );

  const update = useCallback(
    (id: string, patch: Partial<AlgoOrder> | ((a: AlgoOrder) => AlgoOrder)) =>
      persist(
        loadAlgos().map((a) =>
          a.id === id
            ? { ...(typeof patch === "function" ? patch(a) : { ...a, ...patch }), updatedAt: Date.now() }
            : a,
        ),
      ),
    [persist],
  );

  const remove = useCallback(
    (id: string) => persist(loadAlgos().filter((a) => a.id !== id)),
    [persist],
  );

  const setStatus = useCallback(
    (id: string, status: AlgoStatus) => update(id, { status }),
    [update],
  );

  const clearTerminal = useCallback(
    () => persist(loadAlgos().filter((a) => a.status === "running" || a.status === "paused")),
    [persist],
  );

  return { algos, add, update, remove, setStatus, clearTerminal };
}
