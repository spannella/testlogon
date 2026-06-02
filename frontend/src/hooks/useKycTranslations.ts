import { useCallback } from "react";
import { useQuery } from "@tanstack/react-query";

import {
  getKycSupportedLocales,
  getKycTranslationBundle,
} from "@/api/endpoints/kycTranslations";
import type { KycSupportedLocales, KycTranslationBundle } from "@/api/types";

/**
 * Fetch & cache the KYC translation bundle for a locale. Returns a `t()`
 * helper that looks up a key and falls back to the supplied default (or the
 * key itself) when the translation is missing.
 */
export function useKycTranslations(language: string, prefix?: string) {
  const query = useQuery<KycTranslationBundle>({
    queryKey: ["kyc-i18n", "bundle", language, prefix ?? null],
    queryFn: () => getKycTranslationBundle(language, prefix),
    staleTime: 10 * 60 * 1000,
    enabled: !!language,
  });

  const translations = query.data?.translations ?? {};

  const t = useCallback(
    (key: string, fallback?: string): string =>
      translations[key] ?? fallback ?? key,
    [translations],
  );

  return {
    t,
    translations,
    rtl: query.data?.rtl ?? false,
    language: query.data?.language ?? language,
    isLoading: query.isLoading,
    isError: query.isError,
  };
}

/** Fetch the list of supported KYC locales. */
export function useKycSupportedLocales() {
  return useQuery<KycSupportedLocales>({
    queryKey: ["kyc-i18n", "locales"],
    queryFn: getKycSupportedLocales,
    staleTime: 60 * 60 * 1000,
  });
}
