import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/PageHeader";
import { AlertCenter } from "./AlertCenter";
import { AlertPrefs } from "./AlertPrefs";
import { PushDevices } from "./PushDevices";

export default function AlertsPage() {
  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Alerts"
        description="View notifications and manage alert preferences"
      />

      <Tabs defaultValue="alerts">
        <TabsList>
          <TabsTrigger value="alerts">Notifications</TabsTrigger>
          <TabsTrigger value="preferences">Preferences</TabsTrigger>
          <TabsTrigger value="push">Push Devices</TabsTrigger>
        </TabsList>
        <TabsContent value="alerts">
          <AlertCenter />
        </TabsContent>
        <TabsContent value="preferences">
          <AlertPrefs />
        </TabsContent>
        <TabsContent value="push">
          <PushDevices />
        </TabsContent>
      </Tabs>
    </div>
  );
}
