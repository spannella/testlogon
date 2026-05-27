import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";

import en from "./locales/en.json";
import es from "./locales/es.json";
import fr from "./locales/fr.json";

// Supported locales with metadata for the LanguageSwitcher
export const SUPPORTED_LOCALES = [
  { code: "en", name: "English", nativeName: "English", rtl: false },
  { code: "es", name: "Spanish", nativeName: "Español", rtl: false },
  { code: "fr", name: "French", nativeName: "Français", rtl: false },
] as const;

export type LocaleCode = (typeof SUPPORTED_LOCALES)[number]["code"];

const RTL_LOCALES = new Set(["ar", "he", "fa", "ur"]);

export function isRTLLocale(lang: string): boolean {
  return RTL_LOCALES.has(lang?.split("-")[0] ?? "");
}

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
      es: { translation: es },
      fr: { translation: fr },
    },
    fallbackLng: "en",
    supportedLngs: ["en", "es", "fr"],
    ns: ["translation"],
    defaultNS: "translation",
    detection: {
      order: ["localStorage", "navigator"],
      lookupLocalStorage: "i18nextLng",
      caches: ["localStorage"],
    },
    interpolation: {
      escapeValue: false, // React already escapes
    },
    react: {
      useSuspense: false, // We bundle translations statically, no need for suspense
    },
  });

export default i18n;
