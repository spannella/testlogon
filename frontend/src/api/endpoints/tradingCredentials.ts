import { api } from "@/api/client";
import type {
  GatewayEndpoints,
  KeyProtocols,
  RotateProtocolSecretResp,
} from "@/api/types";
import type { Protocol } from "@/lib/tradingCredentials";

// ─── Multi-protocol trading/custody credential clients ───────────
// These are NEW backend endpoints; callers degrade-on-404.

export const getGatewayEndpoints = () =>
  api.get<GatewayEndpoints>("/me/gateway/endpoints");

export const getKeyProtocols = (keyId: string) =>
  api.get<KeyProtocols>(`/ui/api_keys/${keyId}/protocols`);

export const rotateKeyProtocolSecret = (keyId: string, protocol: Protocol) =>
  api.post<RotateProtocolSecretResp>(
    `/ui/api_keys/${keyId}/protocols/${protocol}/rotate`,
  );
