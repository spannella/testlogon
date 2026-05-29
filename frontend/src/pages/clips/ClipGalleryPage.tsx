import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { listGallery, listMyClips } from "@/api/endpoints/clips";
import { ClipCard } from "./ClipCard";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Scissors } from "lucide-react";

export default function ClipGalleryPage() {
  const navigate = useNavigate();
  const [sort, setSort] = useState<"popular" | "recent">("popular");

  const galleryQuery = useQuery({
    queryKey: ["clips", "gallery", sort],
    queryFn: () => listGallery({ sort, limit: 50 }),
  });

  const myClipsQuery = useQuery({
    queryKey: ["clips", "mine"],
    queryFn: () => listMyClips(),
  });

  return (
    <div className="container mx-auto p-6 max-w-6xl">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Scissors className="h-5 w-5" />
            Clip Gallery
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="gallery">
            <TabsList>
              <TabsTrigger value="gallery">Gallery</TabsTrigger>
              <TabsTrigger value="mine">My Clips</TabsTrigger>
            </TabsList>

            <TabsContent value="gallery" className="mt-4">
              <div className="flex gap-2 mb-4">
                <Button
                  variant={sort === "popular" ? "default" : "outline"}
                  size="sm"
                  onClick={() => setSort("popular")}
                >
                  Popular
                </Button>
                <Button
                  variant={sort === "recent" ? "default" : "outline"}
                  size="sm"
                  onClick={() => setSort("recent")}
                >
                  Recent
                </Button>
              </div>

              {galleryQuery.isLoading && (
                <p className="text-muted-foreground">Loading clips...</p>
              )}

              {galleryQuery.data && galleryQuery.data.clips.length === 0 && (
                <p className="text-muted-foreground">No clips yet.</p>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
                {(galleryQuery.data?.clips ?? []).map((clip) => (
                  <ClipCard
                    key={clip.clip_id}
                    clip={clip}
                    onClick={() => navigate(`/clips/${clip.clip_id}`)}
                  />
                ))}
              </div>
            </TabsContent>

            <TabsContent value="mine" className="mt-4">
              {myClipsQuery.isLoading && (
                <p className="text-muted-foreground">Loading your clips...</p>
              )}

              {myClipsQuery.data && myClipsQuery.data.clips.length === 0 && (
                <p className="text-muted-foreground">You haven't created any clips yet.</p>
              )}

              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
                {(myClipsQuery.data?.clips ?? []).map((clip) => (
                  <ClipCard
                    key={clip.clip_id}
                    clip={clip}
                    onClick={() => navigate(`/clips/${clip.clip_id}`)}
                  />
                ))}
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}
