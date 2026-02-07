import { api } from "@/api/client";
import type { Profile, Address, AddressIn } from "@/api/types";

// ─── Profile ─────────────────────────────────────────────────────

export const getProfile = () =>
  api.get<{ profile: Profile }>("/ui/profile");

export const patchProfile = (body: Partial<Profile>) =>
  api.patch<{ profile: Profile }>("/ui/profile", body);

export const replaceProfile = (body: Profile) =>
  api.put<{ profile: Profile }>("/ui/profile", body);

export const getProfileAudit = () =>
  api.get<{ audit: Record<string, unknown>[] }>("/ui/profile/audit");

export const uploadProfilePhoto = (kind: "profile" | "cover", file: File) => {
  const formData = new FormData();
  formData.append("file", file);
  return api.upload<{ profile: Profile; url: string }>(
    `/ui/profile/photos/${kind}/upload`,
    formData,
  );
};

// ─── Addresses ───────────────────────────────────────────────────

export const getAddresses = () =>
  api.get<Address[]>("/ui/addresses");

export const createAddress = (body: AddressIn) =>
  api.post<Address>("/ui/addresses", body);

export const updateAddress = (addressId: string, body: AddressIn) =>
  api.patch<Address>(`/ui/addresses/${addressId}`, body);

export const deleteAddress = (addressId: string) =>
  api.del<{ deleted: boolean }>(`/ui/addresses/${addressId}`);

export const searchAddresses = (query: string) =>
  api.post<{ query: string; matches: Address[] }>("/ui/addresses/search", { query });

export const setPrimaryAddress = (addressId: string) =>
  api.put<Address>("/ui/addresses/primary", { address_id: addressId });
