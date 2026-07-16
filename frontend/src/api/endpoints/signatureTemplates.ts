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
  return api.get<SignatureTemplateListResponse>("/ui/signing/templates");
}

export async function listSignatureTemplateVersions(
  templateKey: string,
): Promise<SignatureTemplateVersionsResponse> {
  return api.get<SignatureTemplateVersionsResponse>(
    `/ui/signing/templates/${encodeURIComponent(templateKey)}/versions`,
  );
}

export async function getSignatureTemplateVersion(
  templateKey: string,
  version: number,
): Promise<SignatureTemplateVersion> {
  return api.get<SignatureTemplateVersion>(
    `/ui/signing/templates/${encodeURIComponent(templateKey)}/versions/${version}`,
  );
}

export async function createSignatureTemplateVersion(
  input: CreateSignatureTemplateVersionInput,
): Promise<SignatureTemplateVersion> {
  return api.post<SignatureTemplateVersion>("/ui/signing/templates", input);
}

export async function checkSignatureTemplateMigration(
  pins: SignatureTemplatePin[],
): Promise<SignatureTemplateMigrationListResponse> {
  return api.post<SignatureTemplateMigrationListResponse>(
    "/ui/signing/templates/migration-check",
    { pins },
  );
}
