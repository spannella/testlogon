import { api } from "@/api/client";
import type {
  SyndicateOpenLicensingConfig,
  SyndicateOpenLicensingContent,
  SyndicateOpenLicensingRegistration,
  SyndicateOpenLicensingExemption,
  SyndicateOpenLicensingTerms,
} from "@/api/types";

const base = (syndicateId: string) =>
  `/ui/syndicates/open-licensing/${syndicateId}`;

export const getOpenLicensingConfig = (syndicateId: string) =>
  api.get<SyndicateOpenLicensingConfig>(base(syndicateId));

export const enableOpenLicensing = (
  syndicateId: string,
  terms: SyndicateOpenLicensingTerms,
) =>
  api.post<SyndicateOpenLicensingConfig>(`${base(syndicateId)}/enable`, { terms });

export const disableOpenLicensing = (syndicateId: string) =>
  api.post<SyndicateOpenLicensingConfig>(`${base(syndicateId)}/disable`, {});

export const updateOpenLicensingTerms = (
  syndicateId: string,
  terms: SyndicateOpenLicensingTerms,
) =>
  api.patch<SyndicateOpenLicensingConfig>(`${base(syndicateId)}/terms`, { terms });

export const registerOpenLicensingContent = (
  syndicateId: string,
  contentId: string,
  contentType: string,
) =>
  api.post<SyndicateOpenLicensingRegistration>(`${base(syndicateId)}/register`, {
    content_id: contentId,
    content_type: contentType,
  });

export const listOpenLicensingContent = (syndicateId: string) =>
  api.get<{ items: SyndicateOpenLicensingContent[] }>(`${base(syndicateId)}/content`);

export const exemptOpenLicensingContent = (syndicateId: string, contentId: string) =>
  api.post<SyndicateOpenLicensingExemption>(`${base(syndicateId)}/exempt/${contentId}`, {});

export const removeOpenLicensingExemption = (syndicateId: string, contentId: string) =>
  api.del<SyndicateOpenLicensingExemption>(`${base(syndicateId)}/exempt/${contentId}`);
