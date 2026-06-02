import { api } from "@/api/client";
import type {
  InstanceTemplate,
  InstanceTemplateListOut,
  CreateTemplateReq,
  UpdateTemplateReq,
  CloneTemplateReq,
  LaunchFromTemplateReq,
  LaunchFromTemplateOut,
} from "@/api/types";

const BASE = "/ui/remote/templates";

export function listTemplates(params?: {
  category?: string;
  target?: string;
  include_system?: boolean;
}): Promise<InstanceTemplateListOut> {
  const q: Record<string, string> = {};
  if (params?.category) q.category = params.category;
  if (params?.target) q.target = params.target;
  if (params?.include_system != null) q.include_system = String(params.include_system);
  return api.get<InstanceTemplateListOut>(BASE, q);
}

export function getTemplate(templateId: string): Promise<InstanceTemplate> {
  return api.get<InstanceTemplate>(`${BASE}/${templateId}`);
}

export function createTemplate(body: CreateTemplateReq): Promise<InstanceTemplate> {
  return api.post<InstanceTemplate>(BASE, body);
}

export function updateTemplate(
  templateId: string,
  body: UpdateTemplateReq,
): Promise<InstanceTemplate> {
  return api.patch<InstanceTemplate>(`${BASE}/${templateId}`, body);
}

export function deleteTemplate(templateId: string): Promise<{ ok: boolean }> {
  return api.del<{ ok: boolean }>(`${BASE}/${templateId}`);
}

export function cloneTemplate(
  templateId: string,
  body: CloneTemplateReq,
): Promise<InstanceTemplate> {
  return api.post<InstanceTemplate>(`${BASE}/${templateId}/clone`, body);
}

export function launchFromTemplate(
  templateId: string,
  body: LaunchFromTemplateReq,
): Promise<LaunchFromTemplateOut> {
  return api.post<LaunchFromTemplateOut>(`${BASE}/${templateId}/launch`, body);
}
