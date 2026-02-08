import { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/shared/PageHeader";
import { PlanBrowser } from "./PlanBrowser";
import { MySubscriptions } from "./MySubscriptions";

export default function SubscriptionsPage() {
  const [creatorId, setCreatorId] = useState("");

  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Subscriptions"
        description="Browse plans and manage your subscriptions"
      />

      <Tabs defaultValue="my-subs">
        <TabsList>
          <TabsTrigger value="my-subs">My Subscriptions</TabsTrigger>
          <TabsTrigger value="browse">Browse Plans</TabsTrigger>
        </TabsList>

        <TabsContent value="my-subs" className="mt-4">
          <MySubscriptions />
        </TabsContent>

        <TabsContent value="browse" className="mt-4 space-y-4">
          <div className="flex items-center gap-2">
            <Input
              placeholder="Enter creator ID to browse plans..."
              value={creatorId}
              onChange={(e) => setCreatorId(e.target.value)}
              className="max-w-sm"
            />
          </div>
          {creatorId.trim() ? (
            <PlanBrowser creatorId={creatorId.trim()} />
          ) : (
            <p className="py-8 text-center text-sm text-muted-foreground">
              Enter a creator ID above to browse their subscription plans.
            </p>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
