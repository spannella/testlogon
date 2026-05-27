import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { isRTLLocale } from "@/i18n";

export function RTLProvider({ children }: { children: React.ReactNode }) {
  const { i18n } = useTranslation();
  const isRTL = isRTLLocale(i18n.language);

  useEffect(() => {
    document.documentElement.dir = isRTL ? "rtl" : "ltr";
    document.documentElement.lang = i18n.language || "en";
  }, [i18n.language, isRTL]);

  return <>{children}</>;
}
