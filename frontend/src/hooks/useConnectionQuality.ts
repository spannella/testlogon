import * as React from "react";

export type ConnectionQuality = "good" | "fair" | "poor" | "unknown";

export interface ConnectionQualityInfo {
  quality: ConnectionQuality;
  rtt: number | null;
  packetLoss: number | null;
}

/**
 * Polls RTCPeerConnection.getStats() every 2 seconds to derive a 3-tier
 * connection quality indicator based on round-trip time and packet loss.
 *
 * Thresholds:
 * - Good: RTT < 150ms AND loss < 2%
 * - Fair: RTT < 300ms AND loss < 5%
 * - Poor: anything worse
 */
export function useConnectionQuality(
  peerConnection: RTCPeerConnection | null | undefined,
  enabled: boolean,
): ConnectionQualityInfo {
  const [info, setInfo] = React.useState<ConnectionQualityInfo>({
    quality: "unknown",
    rtt: null,
    packetLoss: null,
  });

  React.useEffect(() => {
    if (!peerConnection || !enabled) {
      setInfo({ quality: "unknown", rtt: null, packetLoss: null });
      return;
    }

    let cancelled = false;

    const pollStats = async () => {
      if (cancelled) return;

      try {
        const stats = await peerConnection.getStats();
        let totalRoundTripTime = 0;
        let roundTripMeasurements = 0;
        let packetsLost = 0;
        let packetsReceived = 0;

        stats.forEach((report) => {
          if (report.type === "candidate-pair" && report.state === "succeeded") {
            if (typeof report.currentRoundTripTime === "number") {
              totalRoundTripTime += report.currentRoundTripTime;
              roundTripMeasurements += 1;
            }
          }
          if (report.type === "inbound-rtp") {
            packetsLost += report.packetsLost ?? 0;
            packetsReceived += report.packetsReceived ?? 0;
          }
        });

        if (cancelled) return;

        const avgRtt = roundTripMeasurements > 0
          ? totalRoundTripTime / roundTripMeasurements
          : null;

        const totalPackets = packetsLost + packetsReceived;
        const lossRate = totalPackets > 0 ? packetsLost / totalPackets : 0;

        // RTT is in seconds from getStats(); convert to ms for the returned value
        const rttMs = avgRtt !== null ? Math.round(avgRtt * 1000) : null;
        const lossPercent = Math.round(lossRate * 1000) / 10; // one decimal

        let quality: ConnectionQuality;
        if (avgRtt === null) {
          quality = "unknown";
        } else if (avgRtt < 0.15 && lossRate < 0.02) {
          quality = "good";
        } else if (avgRtt < 0.3 && lossRate < 0.05) {
          quality = "fair";
        } else {
          quality = "poor";
        }

        setInfo({ quality, rtt: rttMs, packetLoss: lossPercent });
      } catch {
        if (!cancelled) {
          setInfo({ quality: "unknown", rtt: null, packetLoss: null });
        }
      }
    };

    // Immediate first poll
    pollStats();

    // Poll every 2 seconds
    const interval = window.setInterval(pollStats, 2000);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [peerConnection, enabled]);

  return info;
}
