import * as React from "react";
import { sendCallHeartbeat, type HeartbeatResponse } from "@/api/endpoints/callBilling";
import { ApiError } from "@/api/client";

interface UseCallBillingHeartbeatOptions {
  callId: string | null | undefined;
  /** Only fire when the call is connected AND the rate is paid (rate_cents_per_minute > 0). */
  enabled: boolean;
  /** Default interval in seconds before the first server response is available. */
  defaultIntervalSeconds?: number;
  /** Called when the server signals the call must end (action="end_call" or HTTP 402). */
  onEndCall?: () => void;
  /** Called when the server flags a low balance warning. */
  onLowBalance?: (minutesRemaining: number) => void;
}

const MIN_INTERVAL_SECONDS = 10;

/**
 * Drives the paid-call billing heartbeat loop.
 *
 * During a connected paid call this periodically PATCHes
 * `/messaging/messages/calls/{call_id}/heartbeat` so the backend billing engine
 * fires mid-call billing cycles and can enforce balance depletion. The loop is a
 * self-rescheduling `setTimeout` (not `setInterval`) so the next interval adapts
 * to the server's `next_bill_in_seconds` and requests never overlap.
 *
 * Returns the most recent `HeartbeatResponse` so callers can render live balance.
 */
export function useCallBillingHeartbeat({
  callId,
  enabled,
  defaultIntervalSeconds = 30,
  onEndCall,
  onLowBalance,
}: UseCallBillingHeartbeatOptions): HeartbeatResponse | null {
  const [lastResponse, setLastResponse] = React.useState<HeartbeatResponse | null>(null);
  const timerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const nextIntervalRef = React.useRef(defaultIntervalSeconds);
  const enabledRef = React.useRef(enabled);
  enabledRef.current = enabled;

  const onEndCallRef = React.useRef(onEndCall);
  onEndCallRef.current = onEndCall;
  const onLowBalanceRef = React.useRef(onLowBalance);
  onLowBalanceRef.current = onLowBalance;

  const sendHeartbeat = React.useCallback(async () => {
    if (!callId || !enabledRef.current) return;
    try {
      const resp = await sendCallHeartbeat(callId);
      setLastResponse(resp);
      nextIntervalRef.current = Math.max(
        MIN_INTERVAL_SECONDS,
        resp.next_bill_in_seconds || defaultIntervalSeconds,
      );
      if (resp.action === "end_call") {
        onEndCallRef.current?.();
      } else if (resp.warn_low_balance) {
        onLowBalanceRef.current?.(resp.minutes_remaining);
      }
    } catch (err: unknown) {
      // Balance depleted: backend returns 402 and ends the call server-side.
      // Mirror that on the client so the overlay closes immediately.
      if (err instanceof ApiError && err.status === 402) {
        onEndCallRef.current?.();
        return;
      }
      // Other (transient) network errors: keep the loop running; the backend's
      // heartbeat-timeout path handles a genuinely lapsed client.
    }
  }, [callId, defaultIntervalSeconds]);

  React.useEffect(() => {
    if (!enabled || !callId) return;

    nextIntervalRef.current = defaultIntervalSeconds;

    // Immediate first heartbeat on connect so billing starts from second one.
    void sendHeartbeat();

    const schedule = () => {
      timerRef.current = setTimeout(async () => {
        await sendHeartbeat();
        if (enabledRef.current) schedule();
      }, nextIntervalRef.current * 1000);
    };
    schedule();

    return () => {
      if (timerRef.current !== null) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [enabled, callId, defaultIntervalSeconds, sendHeartbeat]);

  return lastResponse;
}
