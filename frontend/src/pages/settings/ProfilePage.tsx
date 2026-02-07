import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/PageHeader";
import { Profile } from "./Profile";
import { Addresses } from "./Addresses";

export default function ProfilePage() {
  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Profile"
        description="Manage your personal information and addresses"
      />

      <Tabs defaultValue="profile">
        <TabsList>
          <TabsTrigger value="profile">Profile</TabsTrigger>
          <TabsTrigger value="addresses">Addresses</TabsTrigger>
        </TabsList>
        <TabsContent value="profile">
          <Profile />
        </TabsContent>
        <TabsContent value="addresses">
          <Addresses />
        </TabsContent>
      </Tabs>
    </div>
  );
}
