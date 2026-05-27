import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Search, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
  listCountries,
  getVideoGeo,
  setVideoGeo,
  setBroadcastGeo,
  setCatalogGeo,
} from "@/api/endpoints/geo";
import type { GeoCountry, GeoRestrictionRequest } from "@/api/types";

// ─── Country Picker ────────────────────────────────────────────────

function CountryPicker({
  selected,
  onToggle,
  countries,
}: {
  selected: Set<string>;
  onToggle: (code: string) => void;
  countries: GeoCountry[];
}) {
  const [search, setSearch] = useState("");

  const filtered = useMemo(() => {
    if (!search.trim()) return countries;
    const q = search.toLowerCase();
    return countries.filter(
      (c) =>
        c.code.toLowerCase().includes(q) ||
        c.name.toLowerCase().includes(q),
    );
  }, [countries, search]);

  return (
    <div className="space-y-2">
      <div className="relative">
        <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search countries..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-8"
        />
      </div>
      <div className="max-h-48 overflow-y-auto border rounded-md p-2 space-y-1">
        {filtered.map((c) => (
          <label
            key={c.code}
            className="flex items-center gap-2 px-2 py-1 rounded hover:bg-accent cursor-pointer text-sm"
          >
            <input
              type="checkbox"
              checked={selected.has(c.code)}
              onChange={() => onToggle(c.code)}
              className="rounded"
            />
            <span className="font-mono text-xs text-muted-foreground">
              {c.code}
            </span>
            <span>{c.name}</span>
          </label>
        ))}
        {filtered.length === 0 && (
          <p className="text-sm text-muted-foreground px-2 py-4 text-center">
            No countries match your search.
          </p>
        )}
      </div>
    </div>
  );
}

// ─── Editor Props ──────────────────────────────────────────────────

interface GeoRestrictionEditorProps {
  /** Content type determines which API endpoint to use */
  contentType: "video" | "broadcast" | "catalog";
  /** The ID of the content item */
  contentId: string;
}

/**
 * Reusable geo-restriction editor component.
 * Fetches current geo settings, allows editing, and saves changes.
 */
export function GeoRestrictionEditor({
  contentType,
  contentId,
}: GeoRestrictionEditorProps) {
  const queryClient = useQueryClient();

  const { data: countriesData } = useQuery({
    queryKey: ["geo", "countries"],
    queryFn: listCountries,
    staleTime: 24 * 60 * 60 * 1000,
  });

  // Only fetch existing geo data for videos (they have a GET endpoint)
  const { data: geoData, isLoading } = useQuery({
    queryKey: [contentType, contentId, "geo"],
    queryFn: () => getVideoGeo(contentId),
    enabled: contentType === "video",
  });

  const [mode, setMode] = useState<"none" | "allow" | "block">("none");
  const [selectedCountries, setSelectedCountries] = useState<Set<string>>(
    new Set(),
  );
  const [initialized, setInitialized] = useState(false);

  // Sync state when data loads
  useMemo(() => {
    if (geoData && !initialized) {
      setMode(
        (geoData.geo_mode as "none" | "allow" | "block") ?? "none",
      );
      setSelectedCountries(new Set(geoData.geo_countries ?? []));
      setInitialized(true);
    }
  }, [geoData, initialized]);

  const saveMut = useMutation({
    mutationFn: (body: GeoRestrictionRequest) => {
      switch (contentType) {
        case "video":
          return setVideoGeo(contentId, body);
        case "broadcast":
          return setBroadcastGeo(contentId, body);
        case "catalog":
          return setCatalogGeo(contentId, body);
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: [contentType, contentId, "geo"],
      });
      toast.success("Geo restrictions saved");
    },
    onError: () => toast.error("Failed to save geo restrictions"),
  });

  const toggleCountry = (code: string) => {
    setSelectedCountries((prev) => {
      const next = new Set(prev);
      if (next.has(code)) next.delete(code);
      else next.add(code);
      return next;
    });
  };

  const handleSave = () => {
    saveMut.mutate({
      geo_mode: mode === "none" ? null : mode,
      geo_countries:
        mode === "none" ? null : Array.from(selectedCountries),
    });
  };

  const clearAll = () => {
    setMode("none");
    setSelectedCountries(new Set());
  };

  const countries = countriesData?.countries ?? [];

  if (isLoading && contentType === "video") {
    return (
      <p className="text-sm text-muted-foreground">
        Loading geo settings...
      </p>
    );
  }

  return (
    <div className="space-y-4">
      <h3 className="text-sm font-medium">Geo Restrictions</h3>

      <RadioGroup
        value={mode}
        onValueChange={(v: string) =>
          setMode(v as "none" | "allow" | "block")
        }
        className="space-y-2"
      >
        <div className="flex items-center gap-2">
          <RadioGroupItem value="none" id="geo-none" />
          <Label htmlFor="geo-none">
            No restrictions (global access)
          </Label>
        </div>
        <div className="flex items-center gap-2">
          <RadioGroupItem value="allow" id="geo-allow" />
          <Label htmlFor="geo-allow">
            Allow only selected countries
          </Label>
        </div>
        <div className="flex items-center gap-2">
          <RadioGroupItem value="block" id="geo-block" />
          <Label htmlFor="geo-block">Block selected countries</Label>
        </div>
      </RadioGroup>

      {mode !== "none" && (
        <>
          <CountryPicker
            selected={selectedCountries}
            onToggle={toggleCountry}
            countries={countries}
          />

          {selectedCountries.size > 0 && (
            <div className="flex flex-wrap gap-1">
              {Array.from(selectedCountries).map((code) => {
                const c = countries.find((x) => x.code === code);
                return (
                  <Badge
                    key={code}
                    variant="secondary"
                    className="gap-1"
                  >
                    {code} {c ? `- ${c.name}` : ""}
                    <button
                      onClick={() => toggleCountry(code)}
                      className="ml-1 hover:text-destructive"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                );
              })}
            </div>
          )}
        </>
      )}

      <div className="flex gap-2">
        <Button
          onClick={handleSave}
          disabled={
            saveMut.isPending ||
            (mode !== "none" && selectedCountries.size === 0)
          }
        >
          {saveMut.isPending ? "Saving..." : "Save Restrictions"}
        </Button>
        {mode !== "none" && (
          <Button variant="outline" onClick={clearAll}>
            Clear All
          </Button>
        )}
      </div>
    </div>
  );
}
