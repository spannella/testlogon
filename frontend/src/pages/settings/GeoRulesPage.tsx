import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Globe, Shield, MapPin } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  listCountries,
  getMyCountry,
  checkGeoDryRun,
} from "@/api/endpoints/geo";

// Note: Per-video GeoRestrictionEditor component is in
// @/components/shared/GeoRestrictionEditor.tsx for embedding in video edit pages.

// ─── Main Page ─────────────────────────────────────────────────────

export default function GeoRulesPage() {
  const [testMode, setTestMode] = useState<string>("");
  const [testCountries, setTestCountries] = useState<string>("");

  const { data: countriesData } = useQuery({
    queryKey: ["geo", "countries"],
    queryFn: listCountries,
    staleTime: 24 * 60 * 60 * 1000,
  });

  const { data: myCountryData } = useQuery({
    queryKey: ["geo", "my-country"],
    queryFn: getMyCountry,
  });

  const testMut = useMutation({
    mutationFn: () =>
      checkGeoDryRun({
        geo_mode: testMode || undefined,
        geo_countries: testCountries || undefined,
      }),
  });

  const countries = countriesData?.countries ?? [];

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Globe className="h-5 w-5" />
            Geo-Blocking Settings
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* My Country */}
          <div className="flex items-center gap-3 p-3 bg-muted/50 rounded-lg">
            <MapPin className="h-5 w-5 text-muted-foreground" />
            <div>
              <p className="text-sm font-medium">Your Detected Location</p>
              <p className="text-sm text-muted-foreground">
                {myCountryData?.country ? (
                  <>
                    Country: <span className="font-mono">{myCountryData.country}</span>
                    {" "}({countries.find((c) => c.code === myCountryData.country)?.name ?? "Unknown"})
                  </>
                ) : (
                  "Unable to determine (localhost / private IP)"
                )}
                {" | "}IP: <span className="font-mono">{myCountryData?.ip ?? "..."}</span>
                {" | "}Source: {myCountryData?.source ?? "..."}
              </p>
            </div>
          </div>

          {/* Dry-run test */}
          <div className="border rounded-lg p-4 space-y-3">
            <h3 className="text-sm font-medium flex items-center gap-2">
              <Shield className="h-4 w-4" />
              Test Geo Rules
            </h3>
            <p className="text-xs text-muted-foreground">
              Run a dry-run check against your current IP to see if a specific
              geo configuration would block you.
            </p>
            <div className="flex gap-2 flex-wrap">
              <select
                className="border rounded px-2 py-1 text-sm"
                value={testMode}
                onChange={(e) => setTestMode(e.target.value)}
              >
                <option value="">No restriction</option>
                <option value="allow">Allow only</option>
                <option value="block">Block</option>
              </select>
              <Input
                placeholder="Country codes (comma-separated, e.g. US,CA,GB)"
                value={testCountries}
                onChange={(e) => setTestCountries(e.target.value.toUpperCase())}
                className="max-w-xs text-sm"
              />
              <Button
                size="sm"
                variant="outline"
                onClick={() => testMut.mutate()}
                disabled={testMut.isPending}
              >
                {testMut.isPending ? "Checking..." : "Test"}
              </Button>
            </div>
            {testMut.data && (
              <div
                className={`p-2 rounded text-sm ${
                  testMut.data.allowed
                    ? "bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400"
                    : "bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400"
                }`}
              >
                {testMut.data.allowed ? "Access ALLOWED" : "Access BLOCKED"}
                {testMut.data.country && ` (country: ${testMut.data.country})`}
                {testMut.data.matched_rule && ` [rule: ${testMut.data.matched_rule}]`}
              </div>
            )}
          </div>

          {/* Info */}
          <div className="text-sm text-muted-foreground space-y-1">
            <p>
              Geo-restrictions are configured per video, broadcast, or catalog item
              using the editors on each content's detail/edit page.
            </p>
            <p>
              To set restrictions on a specific video, go to the video's edit page
              and use the Geo Restrictions section. The same applies for broadcasts
              and catalog items.
            </p>
            <p>
              Country list: {countries.length} countries available.
              Platform-wide blocks are configured via environment variable{" "}
              <code className="font-mono text-xs">GEO_PLATFORM_BLOCK_COUNTRIES</code>.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
