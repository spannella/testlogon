import { useQuery } from "@tanstack/react-query";
import {
  CalendarDays,
  Contact,
  CreditCard,
  FileBarChart,
  Search,
  Ticket,
  X,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

import { getDashletData, type DashletConfigOut, type DashletType } from "@/api/endpoints/crmReports";
import { fmtCents, fmtTs } from "./reportUtils";

function dashletIcon(type: DashletType) {
  switch (type) {
    case "recent_tickets":
      return Ticket;
    case "calendar_today":
      return CalendarDays;
    case "my_contacts":
      return Contact;
    case "billing_summary":
      return CreditCard;
    case "report":
      return FileBarChart;
    case "saved_search":
      return Search;
    default:
      return FileBarChart;
  }
}

interface DashletCardProps {
  dashlet: DashletConfigOut;
  onRemove: (dashletId: string) => void;
  removing?: boolean;
}

export function DashletCard({ dashlet, onRemove, removing }: DashletCardProps) {
  const Icon = dashletIcon(dashlet.dashlet_type);

  const dataQuery = useQuery({
    queryKey: ["crm-dashboard", "dashlet", dashlet.dashlet_id],
    queryFn: () => getDashletData(dashlet.dashlet_id),
    retry: false,
  });

  return (
    <Card className="flex flex-col">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          <Icon className="h-4 w-4 text-muted-foreground" />
          {dashlet.title}
        </CardTitle>
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7"
          onClick={() => onRemove(dashlet.dashlet_id)}
          disabled={removing}
          aria-label="Remove dashlet"
        >
          <X className="h-4 w-4" />
        </Button>
      </CardHeader>
      <CardContent className="flex-1 text-sm">
        {dataQuery.isLoading ? (
          <Skeleton className="h-20 w-full" />
        ) : dataQuery.isError ? (
          <p className="text-xs text-destructive">Unable to load dashlet data.</p>
        ) : (
          <DashletBody type={dashlet.dashlet_type} data={dataQuery.data?.data ?? {}} />
        )}
        {dataQuery.data?.fetched_at && (
          <p className="mt-3 text-[11px] text-muted-foreground">
            Updated {fmtTs(dataQuery.data.fetched_at)}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function DashletBody({ type, data }: { type: DashletType; data: Record<string, unknown> }) {
  if (type === "billing_summary") {
    const total = Number(data["total_cents"] ?? 0);
    const txCount = Number(data["tx_count"] ?? 0);
    const periodDays = Number(data["period_days"] ?? 0);
    return (
      <div className="space-y-1">
        <p className="text-2xl font-semibold">{fmtCents(total)}</p>
        <p className="text-xs text-muted-foreground">
          {txCount} transaction(s) over {periodDays} day(s)
        </p>
      </div>
    );
  }

  if (type === "recent_tickets") {
    const tickets = (data["tickets"] as Array<Record<string, unknown>>) ?? [];
    if (tickets.length === 0) return <Empty>No recent tickets.</Empty>;
    return (
      <ul className="space-y-1.5">
        {tickets.slice(0, 6).map((t, i) => (
          <li key={i} className="flex items-center justify-between gap-2">
            <span className="truncate">{String(t["subject"] ?? "—")}</span>
            <span className="shrink-0 text-xs text-muted-foreground">{String(t["status"] ?? "")}</span>
          </li>
        ))}
      </ul>
    );
  }

  if (type === "my_contacts") {
    const contacts = (data["contacts"] as Array<Record<string, unknown>>) ?? [];
    if (contacts.length === 0) return <Empty>No contacts.</Empty>;
    return (
      <ul className="space-y-1.5">
        {contacts.slice(0, 6).map((c, i) => (
          <li key={i} className="flex flex-col">
            <span className="truncate font-medium">{String(c["name"] ?? "—")}</span>
            <span className="truncate text-xs text-muted-foreground">{String(c["email"] ?? "")}</span>
          </li>
        ))}
      </ul>
    );
  }

  if (type === "calendar_today") {
    const events = (data["events"] as Array<Record<string, unknown>>) ?? [];
    if (events.length === 0) return <Empty>No events today.</Empty>;
    return (
      <ul className="space-y-1.5">
        {events.slice(0, 6).map((e, i) => (
          <li key={i} className="flex items-center justify-between gap-2">
            <span className="truncate">{String(e["title"] ?? "—")}</span>
            <span className="shrink-0 text-xs text-muted-foreground">
              {String(e["start_utc"] ?? "")}
            </span>
          </li>
        ))}
      </ul>
    );
  }

  if (type === "report" || type === "saved_search") {
    const rowCount = Number(data["row_count"] ?? (Array.isArray(data["rows"]) ? (data["rows"] as unknown[]).length : 0));
    const columns = (data["columns"] as string[]) ?? [];
    return (
      <div className="space-y-1">
        <p className="text-2xl font-semibold">{rowCount}</p>
        <p className="text-xs text-muted-foreground">
          row(s){columns.length ? ` · ${columns.length} column(s)` : ""}
        </p>
      </div>
    );
  }

  return <Empty>No data.</Empty>;
}

function Empty({ children }: { children: React.ReactNode }) {
  return <p className="text-xs text-muted-foreground">{children}</p>;
}
