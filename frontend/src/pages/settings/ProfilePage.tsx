import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/PageHeader";
import { Profile } from "./Profile";
import { Addresses } from "./Addresses";
import { ProfileAudit } from "./ProfileAudit";
import { ProfilePosts } from "./ProfilePosts";
import { isProfilePostsFeedEnabled } from "@/lib/featureFlags";

export default function ProfilePage() {
  const profilePostsEnabled = isProfilePostsFeedEnabled();

  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 sm:p-6">
        <PageHeader
          title="Profile"
          description="Manage your personal information and addresses"
        />

        <Tabs defaultValue="profile">
          <TabsList>
            <TabsTrigger value="profile">Profile</TabsTrigger>
            {profilePostsEnabled ? <TabsTrigger value="posts">Posts</TabsTrigger> : null}
            <TabsTrigger value="addresses">Addresses</TabsTrigger>
            <TabsTrigger value="activity">Activity</TabsTrigger>
          </TabsList>
          <TabsContent value="profile">
            <Profile />
          </TabsContent>
          {profilePostsEnabled ? (
            <TabsContent value="posts">
              <ProfilePosts />
            </TabsContent>
          ) : null}
          <TabsContent value="addresses">
            <Addresses />
          </TabsContent>
          <TabsContent value="activity">
            <ProfileAudit />
          </TabsContent>
        </Tabs>
    </div>
  );
}
