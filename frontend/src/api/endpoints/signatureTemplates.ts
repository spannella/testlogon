import { api } from "@/api/client";

export type SignatureTemplateFieldType =
  | "text"
  | "signature"
  | "initials"
  | "date"
  | "notary_stamp";

export interface SignatureTemplateField {
  id: string;
  type: SignatureTemplateFieldType;
  label: string;
  required: boolean;
}

export interface SignatureTemplateVersion {
  template_key: string;
  version: number;
  display_name: string;
  description: string;
  fields: SignatureTemplateField[];
  created_at: number;
  created_by: string;
  is_active: boolean;
}

export interface SignatureTemplateListResponse {
  templates: SignatureTemplateVersion[];
}

export interface SignatureTemplateVersionsResponse {
  template_key: string;
  versions: SignatureTemplateVersion[];
}

export interface CreateSignatureTemplateVersionInput {
  template_key: string;
  display_name: string;
  description?: string;
  fields: SignatureTemplateField[];
}

export interface SignatureTemplatePin {
  template_key: string;
  version: number;
}

export interface SignatureTemplateMigration {
  template_key: string;
  display_name: string;
  pinned_version: number;
  latest_version: number;
  needs_resigning: boolean;
}

export interface SignatureTemplateMigrationListResponse {
  migrations: SignatureTemplateMigration[];
}

export async function listSignatureTemplates(): Promise<SignatureTemplateListResponse> {
  const { data } = await api.get<SignatureTemplateListResponse>("/ui/signing/templates");
  return data;
}

export async function listSignatureTemplateVersions(
  templateKey: string,
): Promise<SignatureTemplateVersionsResponse> {
  const { data } = await api.get<SignatureTemplateVersionsResponse>(
    `/ui/signing/templates/${encodeURIComponent(templateKey)}/versions`,
  );
  return data;
}

export async function getSignatureTemplateVersion(
  templateKey: string,
  version: number,
): Promise<SignatureTemplateVersion> {
  const { data } = await api.get<SignatureTemplateVersion>(
    `/ui/signing/templates/${encodeURIComponent(templateKey)}/versions/${version}`,
  );
  return data;
}

export async function createSignatureTemplateVersion(
  input: CreateSignatureTemplateVersionInput,
): Promise<SignatureTemplateVersion> {
  const { data } = await api.post<SignatureTemplateVersion>("/ui/signing/templates", input);
  return data;
}

export async function checkSignatureTemplateMigration(
  pins: SignatureTemplatePin[],
): Promise<SignatureTemplateMigrationListResponse> {
  const { data } = await api.post<SignatureTemplateMigrationListResponse>(
    "/ui/signing/templates/migration-check",
    { pins },
  );
  return data;
}
