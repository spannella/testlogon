const FALSEY_FLAG_VALUES = new Set(["0", "false", "no", "off"]);

export function isTipLotteryEnabled(): boolean {
  const envRaw = ((import.meta as any).env?.VITE_NEWSFEED_TIP_LOTTERY_ENABLED ?? "true").toString().trim().toLowerCase();
  if (typeof window !== "undefined" && (window as any).__TIP_LOTTERY_ENABLED__ !== undefined) {
    return Boolean((window as any).__TIP_LOTTERY_ENABLED__);
  }
  return !FALSEY_FLAG_VALUES.has(envRaw);
}
