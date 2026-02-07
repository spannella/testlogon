import { PageHeader } from "@/components/shared/PageHeader";
import { Cart } from "./Cart";

export default function CartPage() {
  return (
    <div className="mx-auto w-full max-w-3xl space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Shopping Cart"
        description="Review your items and proceed to checkout"
      />
      <Cart />
    </div>
  );
}
