import { api } from "@/api/client";
import type { ContactEntry, AddContactReq, UpdateContactReq } from "@/api/types";

const BASE = "/ui/contacts";

export async function getContacts(): Promise<ContactEntry[]> {
  const r = await api.get<{ contacts: ContactEntry[] }>(BASE);
  return r.contacts;
}

export async function addContact(req: AddContactReq): Promise<ContactEntry> {
  return api.post<ContactEntry>(BASE, req);
}

export async function removeContact(contactId: string): Promise<void> {
  return api.del<void>(`${BASE}/${contactId}`);
}

export async function updateContact(
  contactId: string,
  patch: UpdateContactReq,
): Promise<ContactEntry> {
  return api.patch<ContactEntry>(`${BASE}/${contactId}`, patch);
}
