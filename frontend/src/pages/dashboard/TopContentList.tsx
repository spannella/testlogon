import { BarChart3 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/shared/EmptyState";
import type { DashboardTopContentItem } from "@/api/types";

interface TopContentListProps {
  items: DashboardTopContentItem[];
}

export default function TopContentList({ items }: TopContentListProps) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base">Top Content</CardTitle>
      </CardHeader>
      <CardContent>
        {items.length === 0 && (
          <EmptyState
            icon={<BarChart3 className="h-7 w-7" />}
            title="No content data yet"
            description="Your top-performing posts and videos will appear here once they start getting views."
            className="py-8"
          />
        )}
        <ul className="space-y-2">
          {items.slice(0, 5).map((item, idx) => (
            <li key={item.content_id} className="flex items-center justify-between text-sm">
              <div className="flex items-center gap-2 min-w-0">
                <span className="text-muted-foreground font-mono w-4">{idx + 1}.</span>
                <span className="truncate">{item.title}</span>
              </div>
              <span className="text-muted-foreground ml-2 whitespace-nowrap">
                {item.views.toLocaleString()} views
              </span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
