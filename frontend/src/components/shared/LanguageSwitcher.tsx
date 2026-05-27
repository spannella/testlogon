import { useTranslation } from "react-i18next";
import { Globe } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { SUPPORTED_LOCALES } from "@/i18n";
import { useMutation } from "@tanstack/react-query";
import { saveUserLocale } from "@/api/endpoints/i18n";

/**
 * Language switcher dropdown. Changes the UI language immediately and
 * persists the preference to the backend profile (locale field).
 */
export function LanguageSwitcher() {
  const { i18n, t } = useTranslation();

  const saveLocale = useMutation({
    mutationFn: async (locale: string) => {
      try {
        await saveUserLocale(locale);
      } catch {
        // Best-effort save — locale is also persisted in localStorage
      }
    },
  });

  const handleChange = (locale: string) => {
    i18n.changeLanguage(locale);
    localStorage.setItem("i18nextLng", locale);
    document.documentElement.lang = locale;
    saveLocale.mutate(locale);
  };

  return (
    <div className="space-y-2">
      <Label htmlFor="language-select" className="flex items-center gap-2">
        <Globe className="h-4 w-4" />
        {t("settings.language")}
      </Label>
      <p className="text-sm text-muted-foreground">
        {t("settings.languageDescription")}
      </p>
      <Select value={i18n.language} onValueChange={handleChange}>
        <SelectTrigger id="language-select" className="w-64">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {SUPPORTED_LOCALES.map((loc) => (
            <SelectItem key={loc.code} value={loc.code}>
              {loc.nativeName} ({loc.name})
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}
