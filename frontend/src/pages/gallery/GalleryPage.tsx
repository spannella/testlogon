import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search, Loader2 } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import GalleryVideoCard from "./GalleryVideoCard";
import { browseGallery, searchGallery } from "@/api/endpoints/gallery";
import type { GalleryCategory } from "@/api/endpoints/gallery";
import ForYouTab from "@/pages/videos/ForYouTab";
import CreatorSuggestions from "@/pages/videos/CreatorSuggestions";

export default function GalleryPage() {
  const [activeTab, setActiveTab] = useState("for-you");
  const [category, setCategory] = useState<string | undefined>(undefined);
  const [searchQuery, setSearchQuery] = useState("");
  const [activeSearch, setActiveSearch] = useState("");

  const isSearching = activeSearch.length > 0;

  const browseQ = useQuery({
    queryKey: ["gallery", "browse", category],
    queryFn: () => browseGallery({ category, limit: 48 }),
    enabled: activeTab === "browse" && !isSearching,
  });

  const searchQ = useQuery({
    queryKey: ["gallery", "search", activeSearch],
    queryFn: () => searchGallery({ q: activeSearch, limit: 48 }),
    enabled: isSearching,
  });

  const videos = isSearching
    ? searchQ.data?.videos ?? []
    : browseQ.data?.videos ?? [];

  const categories: GalleryCategory[] = browseQ.data?.categories ?? [];

  const isLoading = isSearching ? searchQ.isLoading : browseQ.isLoading;

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setActiveSearch(searchQuery.trim());
    if (searchQuery.trim()) {
      setCategory(undefined);
      setActiveTab("browse");
    }
  }

  function handleCategoryClick(slug: string | undefined) {
    setCategory(slug);
    setActiveSearch("");
    setSearchQuery("");
  }

  return (
    <div className="mx-auto w-full max-w-7xl space-y-6 p-4 md:p-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-2xl">Video Gallery</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Search bar */}
          <form onSubmit={handleSearch} className="flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search videos..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <Button type="submit" variant="secondary">
              Search
            </Button>
            {isSearching && (
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  setSearchQuery("");
                  setActiveSearch("");
                }}
              >
                Clear
              </Button>
            )}
          </form>

          {/* Tabs */}
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList>
              <TabsTrigger value="for-you">For You</TabsTrigger>
              <TabsTrigger value="browse">Browse</TabsTrigger>
            </TabsList>

            <TabsContent value="for-you" className="mt-4">
              <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_280px]">
                <ForYouTab />
                <div className="hidden lg:block">
                  <CreatorSuggestions />
                </div>
              </div>
            </TabsContent>

            <TabsContent value="browse" className="mt-4">
              {/* Category pills */}
              {!isSearching && categories.length > 0 && (
                <div className="flex flex-wrap gap-2 mb-4">
                  <Button
                    size="sm"
                    variant={category === undefined ? "default" : "outline"}
                    onClick={() => handleCategoryClick(undefined)}
                  >
                    All
                  </Button>
                  {categories.map((cat) => (
                    <Button
                      key={cat.slug}
                      size="sm"
                      variant={category === cat.slug ? "default" : "outline"}
                      onClick={() => handleCategoryClick(cat.slug)}
                    >
                      {cat.label}
                    </Button>
                  ))}
                </div>
              )}

              {/* Loading */}
              {isLoading && (
                <div className="flex items-center justify-center py-16">
                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                </div>
              )}

              {/* Videos grid */}
              {!isLoading && videos.length > 0 && (
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4">
                  {videos.map((v) => (
                    <GalleryVideoCard key={v.video_id} video={v} />
                  ))}
                </div>
              )}

              {/* Empty state */}
              {!isLoading && videos.length === 0 && (
                <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                  <p className="text-lg font-medium">No videos found</p>
                  <p className="text-sm">
                    {isSearching
                      ? "Try a different search term."
                      : "No videos have been published to the gallery yet."}
                  </p>
                </div>
              )}
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}
