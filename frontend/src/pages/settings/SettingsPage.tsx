import { PageHeader } from "@/components/shared/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Account } from "./Account";
import { Appearance } from "./Appearance";

export default function SettingsPage() {
  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Settings"
        description="Manage your account status and preferences"
      />

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Appearance</CardTitle>
        </CardHeader>
        <Separator />
        <CardContent className="pt-4">
          <Appearance />
        </CardContent>
      </Card>

      <Account />
    </div>
  );
}
