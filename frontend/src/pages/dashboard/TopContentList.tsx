import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
          <p className="text-sm text-muted-foreground">No content data yet</p>
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
