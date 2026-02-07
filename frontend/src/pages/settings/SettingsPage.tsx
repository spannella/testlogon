import { PageHeader } from "@/components/shared/PageHeader";
import { Account } from "./Account";

export default function SettingsPage() {
  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Settings"
        description="Manage your account status and preferences"
      />
      <Account />
    </div>
  );
}
