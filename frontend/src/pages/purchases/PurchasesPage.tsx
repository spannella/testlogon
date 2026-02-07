import { useParams } from "react-router-dom";
import { PageHeader } from "@/components/shared/PageHeader";
import { PurchaseHistory } from "./PurchaseHistory";
import { TransactionDetail } from "./TransactionDetail";

export default function PurchasesPage() {
  const { txnId } = useParams<{ txnId: string }>();

  return (
    <div className="mx-auto w-full max-w-4xl space-y-6 p-4 sm:p-6">
      {txnId ? (
        <TransactionDetail />
      ) : (
        <>
          <PageHeader
            title="Orders"
            description="View your purchase history and track orders"
          />
          <PurchaseHistory />
        </>
      )}
    </div>
  );
}
