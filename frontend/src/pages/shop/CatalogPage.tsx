import { PageHeader } from "@/components/shared/PageHeader";
import { Catalog } from "./Catalog";

export default function CatalogPage() {
  return (
    <div className="mx-auto w-full max-w-6xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Shop"
        description="Browse products and add them to your cart"
      />
      <Catalog />
    </div>
  );
}
