import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { browseLibrary } from "@/api/endpoints/issuedLicenses";
import { Scale } from "lucide-react";
import type { LibraryItemOut } from "@/api/types";

const CONTENT_TYPES = ["all", "video", "music", "image", "post", "broadcast", "clip"] as const;

function formatTerms(item: LibraryItemOut) {
  const parts: string[] = [];
  if (item.profit_share_pct) parts.push(`${item.profit_share_pct}% profit share`);
  if (item.fixed_cost_cents) parts.push(`$${(item.fixed_cost_cents / 100).toFixed(2)} fixed`);
  return parts.length > 0 ? parts.join(" + ") : "Free";
}

export default function LicensedLibraryPage() {
  const [contentType, setContentType] = useState<string>("all");

  const { data, isLoading } = useQuery({
    queryKey: ["licensed-library", contentType],
    queryFn: () =>
      browseLibrary({
        content_type: contentType === "all" ? undefined : contentType,
      }),
  });

  const items = data?.items ?? [];

  return (
    <div className="space-y-6 p-6">
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Scale className="h-5 w-5" />
            <CardTitle>Licensed Content Library</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <div className="mb-4 flex gap-4">
            <Select value={contentType} onValueChange={setContentType}>
              <SelectTrigger className="w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {CONTENT_TYPES.map((ct) => (
                  <SelectItem key={ct} value={ct}>
                    {ct === "all" ? "All Types" : ct.charAt(0).toUpperCase() + ct.slice(1)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {isLoading ? (
            <p className="text-muted-foreground py-8 text-center">Loading...</p>
          ) : items.length === 0 ? (
            <p className="text-muted-foreground py-8 text-center">
              No licensed content available yet.
            </p>
          ) : (
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {items.map((item) => (
                <Card key={`${item.content_id}-${item.licensor_id}`}>
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between">
                      <div>
                        <h3 className="font-semibold">
                          {item.title || item.content_id}
                        </h3>
                        <p className="text-muted-foreground text-sm">
                          by {item.licensor_display_name || item.licensor_id}
                        </p>
                      </div>
                      <Badge variant="outline">{item.content_type}</Badge>
                    </div>
                    <div className="mt-2 flex items-center gap-2">
                      <Badge variant="default">Licensed</Badge>
                      <span className="text-muted-foreground text-xs">
                        {formatTerms(item)}
                      </span>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
