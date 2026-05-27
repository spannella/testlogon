import { api } from "@/api/client";

export interface LocaleInfo {
  code: string;
  name: string;
  native_name: string;
  rtl: boolean;
}

export interface LocalesResponse {
  locales: LocaleInfo[];
}

export interface TranslationsResponse {
  locale: string;
  translations: Record<string, string>;
}

export interface UserLocaleResponse {
  locale: string;
}

/** List all available locales with display names (public, no auth). */
export async function getLocales(): Promise<LocalesResponse> {
  return api<LocalesResponse>("/ui/i18n/locales");
}

/** Get all translations for a locale (public, no auth). */
export async function getTranslations(locale: string): Promise<TranslationsResponse> {
  return api<TranslationsResponse>(`/ui/i18n/translations/${locale}`);
}

/** Get the authenticated user's saved locale preference. */
export async function getUserLocale(): Promise<UserLocaleResponse> {
  return api<UserLocaleResponse>("/ui/i18n/locale");
}

/** Save the user's locale preference. */
export async function saveUserLocale(locale: string): Promise<{ ok: boolean; locale: string }> {
  return api<{ ok: boolean; locale: string }>("/ui/i18n/locale", {
    method: "PUT",
    body: JSON.stringify({ locale }),
    headers: { "Content-Type": "application/json" },
  });
}
