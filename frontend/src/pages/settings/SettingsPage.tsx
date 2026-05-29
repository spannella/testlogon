import { useTranslation } from "react-i18next";
import { PageHeader } from "@/components/shared/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { LanguageSwitcher } from "@/components/shared/LanguageSwitcher";
import { Account } from "./Account";
import { Appearance } from "./Appearance";
import { AppearanceSection } from "./AppearanceSection";
import { JiraIntegrationSettings } from "./JiraIntegrationSettings";

export default function SettingsPage() {
  const { t } = useTranslation();

  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title={t("settings.title")}
        description={t("settings.description")}
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">{t("settings.language")}</CardTitle>
        </CardHeader>
        <Separator />
        <CardContent className="pt-4">
          <LanguageSwitcher />
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">{t("settings.appearance")}</CardTitle>
        </CardHeader>
        <Separator />
        <CardContent className="pt-4">
          <Appearance />
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Customization</CardTitle>
        </CardHeader>
        <Separator />
        <CardContent className="pt-4">
          <AppearanceSection />
        </CardContent>
      </Card>

      <Account />

      <JiraIntegrationSettings />
    </div>
  );
}
