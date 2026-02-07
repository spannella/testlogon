import { PageHeader } from "@/components/shared/PageHeader";
import { PurchaseHistory } from "./PurchaseHistory";

export default function PurchasesPage() {
  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Orders"
        description="View your purchase history and track orders"
      />
      <PurchaseHistory />
    </div>
  );
}
