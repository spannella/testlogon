import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/PageHeader";
import { MfaDevices } from "./MfaDevices";
import { Sessions } from "./Sessions";
import { TrustedDevices } from "./TrustedDevices";
import { ApiKeys } from "./ApiKeys";
import { Recovery } from "./Recovery";

export default function SecurityPage() {
  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Security"
        description="Manage MFA devices, sessions, API keys, and recovery options"
      />

      <Tabs defaultValue="mfa">
        <TabsList className="flex-wrap">
          <TabsTrigger value="mfa">MFA Devices</TabsTrigger>
          <TabsTrigger value="sessions">Sessions</TabsTrigger>
          <TabsTrigger value="devices">Trusted Devices</TabsTrigger>
          <TabsTrigger value="apikeys">API Keys</TabsTrigger>
          <TabsTrigger value="recovery">Recovery</TabsTrigger>
        </TabsList>
        <TabsContent value="mfa">
          <MfaDevices />
        </TabsContent>
        <TabsContent value="sessions">
          <Sessions />
        </TabsContent>
        <TabsContent value="devices">
          <TrustedDevices />
        </TabsContent>
        <TabsContent value="apikeys">
          <ApiKeys />
        </TabsContent>
        <TabsContent value="recovery">
          <Recovery />
        </TabsContent>
      </Tabs>
    </div>
  );
}
