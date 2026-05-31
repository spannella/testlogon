import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { CalendarDays } from "lucide-react";
import { getCalendar } from "@/api/endpoints/marketingAgent";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

function currentMonth(): string {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
}

function shiftMonth(month: string, delta: number): string {
  const [y, m] = month.split("-").map(Number);
  const d = new Date(y, (m - 1) + delta, 1);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
}

const TYPE_COLORS: Record<string, string> = {
  blog_post: "bg-blue-500",
  social_twitter: "bg-sky-500",
  social_linkedin: "bg-indigo-500",
  newsletter: "bg-amber-500",
  release_notes: "bg-green-500",
  changelog: "bg-purple-500",
};

export default function MarketingContentCalendarPage() {
  const [month, setMonth] = useState(currentMonth());

  const { data, isLoading } = useQuery({
    queryKey: ["marketing-calendar", month],
    queryFn: () => getCalendar(month),
    staleTime: 5_000,
  });

  const entries = data ?? [];

  return (
    <div data-testid="content-calendar-page" className="space-y-4 p-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <CalendarDays className="h-6 w-6" />
          <h1 className="text-2xl font-bold">Content Calendar</h1>
        </div>
        <Button asChild variant="outline" size="sm">
          <Link to="/agents/marketing">Back to Content</Link>
        </Button>
      </div>

      <div className="flex items-center gap-3" data-testid="calendar-nav">
        <Button size="sm" variant="outline" onClick={() => setMonth((m) => shiftMonth(m, -1))}>
          Prev
        </Button>
        <span className="font-semibold" data-testid="calendar-month">
          {month}
        </span>
        <Button size="sm" variant="outline" onClick={() => setMonth((m) => shiftMonth(m, 1))}>
          Next
        </Button>
        <Button size="sm" variant="ghost" onClick={() => setMonth(currentMonth())}>
          Today
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Scheduled &amp; Published</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p>Loading…</p>
          ) : entries.length === 0 ? (
            <p data-testid="calendar-empty" className="text-muted-foreground">
              No scheduled or published content this month.
            </p>
          ) : (
            <ul className="space-y-2" data-testid="calendar-entries">
              {entries.map((e) => (
                <li
                  key={e.content_id}
                  className="flex items-center gap-3 rounded border p-2"
                  data-testid="calendar-entry"
                >
                  <span
                    className={`h-3 w-3 rounded-full ${TYPE_COLORS[e.content_type] ?? "bg-gray-400"}`}
                  />
                  <span className="text-sm text-muted-foreground">
                    {new Date(e.date * 1000).toLocaleDateString()}
                  </span>
                  <Link
                    to={`/agents/marketing/content/${e.content_id}`}
                    className="flex-1 truncate text-sm hover:underline"
                  >
                    {e.title}
                  </Link>
                  <Badge variant="outline">{e.content_type}</Badge>
                  <Badge variant="secondary">{e.status}</Badge>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
