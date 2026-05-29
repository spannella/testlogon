import { useState } from "react";
import { FileText, Radio, Video } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { ContentItemType } from "@/api/types";

interface Props {
  open: boolean;
  scheduledAt: number;
  onClose: () => void;
  onCreated: () => void;
}

export function QuickScheduleDialog({ open, scheduledAt, onClose, onCreated }: Props) {
  const [type, setType] = useState<ContentItemType>("post");
  const localTime = new Date(scheduledAt * 1000).toLocaleString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Quick Schedule</DialogTitle>
          <DialogDescription>
            Create new content scheduled for {localTime}
          </DialogDescription>
        </DialogHeader>

        <Tabs value={type} onValueChange={(v) => setType(v as ContentItemType)}>
          <TabsList className="w-full">
            <TabsTrigger value="post" className="flex-1 gap-1">
              <FileText className="h-3.5 w-3.5" /> Post
            </TabsTrigger>
            <TabsTrigger value="broadcast" className="flex-1 gap-1">
              <Radio className="h-3.5 w-3.5" /> Broadcast
            </TabsTrigger>
            <TabsTrigger value="vod" className="flex-1 gap-1">
              <Video className="h-3.5 w-3.5" /> Video
            </TabsTrigger>
          </TabsList>

          <TabsContent value="post" className="space-y-3 pt-2">
            <div>
              <Label>Post body</Label>
              <Textarea placeholder="What do you want to share?" rows={3} />
            </div>
            <Button className="w-full" onClick={() => { onCreated(); }}>
              Schedule Post
            </Button>
          </TabsContent>

          <TabsContent value="broadcast" className="space-y-3 pt-2">
            <div>
              <Label>Broadcast name</Label>
              <Input placeholder="My Live Stream" />
            </div>
            <div>
              <Label>Description (optional)</Label>
              <Textarea placeholder="What will you be streaming?" rows={2} />
            </div>
            <Button className="w-full" onClick={() => { onCreated(); }}>
              Schedule Broadcast
            </Button>
          </TabsContent>

          <TabsContent value="vod" className="space-y-3 pt-2">
            <p className="text-sm text-muted-foreground">
              To schedule a video release, upload the video first in the Video Manager,
              then set the release date.
            </p>
            <Button variant="outline" className="w-full" onClick={onClose}>
              Go to Video Manager
            </Button>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
