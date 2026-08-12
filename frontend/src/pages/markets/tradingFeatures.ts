/**
 * Staged trading-feature flags for the web ticket. These mirror the Android
 * `TradingFeatures` staged surfaces and are all OFF by default so the shipped
 * UI is unchanged.
 *
 * Current backend reality (flip when the backend port lands):
 *  - OCO      -> `/me/oco` returns no_response through the prod edge.
 *  - FUNDING  -> `/me/funding_order` rejects with reason 30.
 *  - SPOT     -> `/me/spot_balance` / deposit need an asset-id map first.
 */
export const tradingFeatures = {
  OCO_ENABLED: false,
  FUNDING_ENABLED: false,
  SPOT_ENABLED: false,
} as const;
