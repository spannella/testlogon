import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, FileText } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { PageHeader } from "@/components/shared/PageHeader";
import { listInvoices } from "@/api/endpoints/invoices";
import type { Invoice } from "@/api/types";
import { InvoiceRow } from "./InvoiceRow";

const TYPES = [
  { value: "all", label: "All types" },
  { value: "tip", label: "Tip" },
  { value: "unlock", label: "Unlock" },
  { value: "subscription", label: "Subscription" },
  { value: "shop", label: "Shop" },
  { value: "deposit", label: "Deposit" },
];

function toEpoch(dateStr: string): number | undefined {
  if (!dateStr) return undefined;
  const ms = Date.parse(dateStr);
  if (Number.isNaN(ms)) return undefined;
  return Math.floor(ms / 1000);
}

export default function InvoicesPage() {
  const [type, setType] = useState("all");
  const [search, setSearch] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");

  const query = useQuery({
    queryKey: ["invoices", type, dateFrom, dateTo],
    queryFn: () =>
      listInvoices({
        type: type === "all" ? undefined : type,
        date_from: toEpoch(dateFrom),
        date_to: toEpoch(dateTo),
        limit: 100,
      }),
  });

  const invoices: Invoice[] = useMemo(() => {
    const all = query.data?.invoices ?? [];
    const term = search.trim().toLowerCase();
    if (!term) return all;
    return all.filter((inv) => inv.invoice_number.toLowerCase().includes(term));
  }, [query.data, search]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Invoices"
        description="Download or email PDF invoices for your transactions."
        actions={
          <Button variant="ghost" size="sm" asChild>
            <Link to="/billing">
              <ArrowLeft className="h-4 w-4 mr-1" /> Billing
            </Link>
          </Button>
        }
      />

      <div className="flex flex-wrap items-center gap-3">
        <Select value={type} onValueChange={setType}>
          <SelectTrigger className="w-40" aria-label="Filter by type">
            <SelectValue placeholder="Type" />
          </SelectTrigger>
          <SelectContent>
            {TYPES.map((t) => (
              <SelectItem key={t.value} value={t.value}>
                {t.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          type="date"
          value={dateFrom}
          onChange={(e) => setDateFrom(e.target.value)}
          className="w-40"
          aria-label="From date"
        />
        <Input
          type="date"
          value={dateTo}
          onChange={(e) => setDateTo(e.target.value)}
          className="w-40"
          aria-label="To date"
        />
        <Input
          placeholder="Search invoice number..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-56"
          aria-label="Search invoice number"
        />
      </div>

      {query.isLoading ? (
        <div className="space-y-3">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-20 w-full" />
          ))}
        </div>
      ) : invoices.length === 0 ? (
        <EmptyState
          icon={<FileText className="h-8 w-8" />}
          title="No invoices yet"
          description="Invoices are generated automatically when you make a purchase."
        />
      ) : (
        <div className="space-y-3" data-testid="invoice-list">
          {invoices.map((inv) => (
            <InvoiceRow key={inv.invoice_number} invoice={inv} />
          ))}
        </div>
      )}
    </div>
  );
}
