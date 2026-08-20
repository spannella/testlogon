import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { Phone, Keyboard } from "lucide-react";
import { PageHeader } from "@/components/shared/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { LanguageSwitcher } from "@/components/shared/LanguageSwitcher";
import { Account } from "./Account";
import { Appearance } from "./Appearance";
import { AppearanceSection } from "./AppearanceSection";
import { JiraIntegrationSettings } from "./JiraIntegrationSettings";
import { TradingSettings } from "./TradingSettings";
import { openShortcutsHelp } from "@/components/layout/KeyboardShortcutsHost";

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

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Theme Customization</CardTitle>
        </CardHeader>
        <Separator />
        <CardContent className="pt-4">
          <p className="mb-3 text-sm text-muted-foreground">
            Personalize accent color, font size, density, presets, and high
            contrast. Saved to your account and applied on every device.
          </p>
          <a
            href="/settings/theme"
            className="text-sm font-medium text-primary underline-offset-4 hover:underline"
          >
            Open Theme Customization
          </a>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Phone className="h-4 w-4" />
            Call Rate
          </CardTitle>
        </CardHeader>
        <Separator />
        <CardContent className="pt-4">
          <p className="mb-3 text-sm text-muted-foreground">
            Configure your per-minute rate to enable paid calls from other
            users.
          </p>
          <Button variant="outline" asChild>
            <Link to="/settings/call-rate" data-testid="call-rate-settings-link">
              Manage Call Rate
            </Link>
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Keyboard className="h-4 w-4" />
            Keyboard shortcuts
          </CardTitle>
        </CardHeader>
        <Separator />
        <CardContent className="pt-4">
          <p className="mb-3 text-sm text-muted-foreground">
            Power-user navigation and trading hotkeys. Press{" "}
            <kbd className="rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-xs">?</kbd>{" "}
            anywhere to view them, or toggle them on and off.
          </p>
          <Button variant="outline" onClick={() => openShortcutsHelp()}>
            View keyboard shortcuts
          </Button>
        </CardContent>
      </Card>

      <TradingSettings />

      <Account />

      <JiraIntegrationSettings />
    </div>
  );
}
