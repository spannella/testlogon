import { api } from "@/api/client";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface DriveFile {
  id: string;
  name: string;
  mimeType: string;
  size?: string;
  modifiedTime?: string;
  parents?: string[];
  kind?: string;
}

export interface DriveStatusResp {
  connected: boolean;
  email?: string;
  scopes?: string[];
  connected_at?: string;
}

export interface DriveFilesResp {
  files: DriveFile[];
  nextPageToken?: string;
}

export interface DriveImportResp {
  ok: boolean;
  node_id: string;
  path: string;
}

// ── Status ────────────────────────────────────────────────────────────────────

export const getGoogleDriveStatus = () =>
  api.get<DriveStatusResp>("/ui/integrations/google-drive/status");

// ── Connect / Disconnect ──────────────────────────────────────────────────────

export const initiateGoogleDriveConnect = () =>
  api.get<{ auth_url: string; mock?: boolean }>(
    "/ui/integrations/google-drive/connect",
  );

export const completeGoogleDriveConnect = (
  code: string,
  redirectUri?: string,
  state?: string,
) =>
  api.post<{ ok: boolean; connected: boolean }>(
    "/ui/integrations/google-drive/callback",
    {
      code,
      redirect_uri: redirectUri || "",
      state: state || null,
    },
  );

export const disconnectGoogleDrive = () =>
  api.post<{ ok: boolean }>("/ui/integrations/google-drive/disconnect");

// ── Browse ────────────────────────────────────────────────────────────────────

export const browseGoogleDriveFiles = (params: {
  folder_id?: string;
  q?: string;
  page_token?: string;
  page_size?: number;
}) => {
  const queryParams: Record<string, string> = {};
  if (params.folder_id) queryParams.folder_id = params.folder_id;
  if (params.q) queryParams.q = params.q;
  if (params.page_token) queryParams.page_token = params.page_token;
  if (params.page_size) queryParams.page_size = String(params.page_size);
  return api.get<DriveFilesResp>("/ui/integrations/google-drive/files", queryParams);
};

// ── Import ────────────────────────────────────────────────────────────────────

export const importDriveFile = (
  fileId: string,
  destinationPath?: string,
) =>
  api.post<DriveImportResp>("/ui/integrations/google-drive/import", {
    file_id: fileId,
    destination_path: destinationPath || null,
  });
