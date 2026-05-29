import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { createParty } from "@/api/endpoints/watchParties";
import { Plus } from "lucide-react";

export default function CreatePartyDialog() {
  const [open, setOpen] = useState(false);
  const [videoId, setVideoId] = useState("");
  const [title, setTitle] = useState("");
  const [maxParticipants, setMaxParticipants] = useState(50);
  const qc = useQueryClient();

  const mutation = useMutation({
    mutationFn: () =>
      createParty({
        video_id: videoId,
        title: title || undefined,
        max_participants: maxParticipants,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["watch-parties"] });
      setOpen(false);
      setVideoId("");
      setTitle("");
      setMaxParticipants(50);
    },
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus className="h-4 w-4 mr-2" />
          Create Watch Party
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create Watch Party</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label htmlFor="videoId">Video ID</Label>
            <Input
              id="videoId"
              value={videoId}
              onChange={(e) => setVideoId(e.target.value)}
              placeholder="Enter video ID"
            />
          </div>
          <div>
            <Label htmlFor="title">Party Title (optional)</Label>
            <Input
              id="title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Give your party a name"
            />
          </div>
          <div>
            <Label htmlFor="maxParticipants">Max Participants</Label>
            <Input
              id="maxParticipants"
              type="number"
              min={2}
              max={500}
              value={maxParticipants}
              onChange={(e) => setMaxParticipants(Number(e.target.value))}
            />
          </div>
          <Button
            className="w-full"
            disabled={!videoId || mutation.isPending}
            onClick={() => mutation.mutate()}
          >
            {mutation.isPending ? "Creating..." : "Create Party"}
          </Button>
          {mutation.isError && (
            <p className="text-sm text-red-500">
              {(mutation.error as any)?.response?.data?.detail || "Failed to create party"}
            </p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
