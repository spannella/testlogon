import { api } from "@/api/client";
import type {
  CreateShareLinkInput,
  ShareLink,
  ShareLinkList,
  ShareLinkPublicInfo,
} from "@/api/types";

// ---- Authenticated owner management (cookie + CSRF via api client) ----

export const createShareLink = (data: CreateShareLinkInput) =>
  api.post<ShareLink>("/ui/files/share-links", data);

export const listShareLinks = () =>
  api.get<ShareLinkList>("/ui/files/share-links");

export const revokeShareLink = (linkId: string) =>
  api.del<{ ok: boolean; link_id: string }>(
    `/ui/files/share-links/${encodeURIComponent(linkId)}`,
  );

// ---- Public recipient endpoints (no auth — use raw fetch) ----

export const getShareLinkInfo = async (
  linkId: string,
): Promise<ShareLinkPublicInfo> => {
  const resp = await fetch(
    `/public/files/share/${encodeURIComponent(linkId)}/info`,
    { headers: { Accept: "application/json" } },
  );
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw Object.assign(new Error(err?.detail || "Share link unavailable"), {
      status: resp.status,
      detail: err?.detail,
    });
  }
  return (await resp.json()) as ShareLinkPublicInfo;
};

export const downloadShareLink = async (
  linkId: string,
  password?: string,
): Promise<{ blob: Blob; fileName: string }> => {
  const resp = await fetch(
    `/public/files/share/${encodeURIComponent(linkId)}/download`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: password ?? null }),
    },
  );
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({}));
    throw Object.assign(new Error(err?.detail || "Download failed"), {
      status: resp.status,
      detail: err?.detail,
    });
  }
  const disposition = resp.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="([^"]+)"/);
  const fileName = match ? match[1] : "download";
  const blob = await resp.blob();
  return { blob, fileName };
};
