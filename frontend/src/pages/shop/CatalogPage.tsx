import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/PageHeader";
import { Catalog } from "./Catalog";
import { AdminCatalog } from "./AdminCatalog";

export default function CatalogPage() {
  return (
    <div className="mx-auto w-full max-w-6xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Shop"
        description="Browse products and manage your catalog"
      />
      <Tabs defaultValue="browse">
        <TabsList>
          <TabsTrigger value="browse">Browse</TabsTrigger>
          <TabsTrigger value="manage">Manage</TabsTrigger>
        </TabsList>
        <TabsContent value="browse">
          <Catalog />
        </TabsContent>
        <TabsContent value="manage">
          <AdminCatalog />
        </TabsContent>
      </Tabs>
    </div>
  );
}
