import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Settings } from "lucide-react";
import { getMilestoneSettings, updateMilestoneSettings } from "@/api/endpoints/dashboard";

export default function MilestoneSettingsDialog() {
  const [open, setOpen] = useState(false);
  const queryClient = useQueryClient();

  const { data: settings } = useQuery({
    queryKey: ["milestone-settings"],
    queryFn: getMilestoneSettings,
    enabled: open,
  });

  const mutation = useMutation({
    mutationFn: (data: Record<string, boolean>) => updateMilestoneSettings(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["milestone-settings"] });
    },
  });

  const handleToggle = (key: string, value: boolean) => {
    mutation.mutate({ [key]: value });
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" aria-label="Milestone Settings">
          <Settings className="h-4 w-4" />
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Milestone Settings</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 py-4">
          <div className="flex items-center justify-between">
            <Label htmlFor="push_enabled">Push notifications</Label>
            <Switch
              id="push_enabled"
              checked={settings?.push_enabled ?? true}
              onCheckedChange={(v) => handleToggle("push_enabled", v)}
            />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="email_enabled">Email notifications</Label>
            <Switch
              id="email_enabled"
              checked={settings?.email_enabled ?? true}
              onCheckedChange={(v) => handleToggle("email_enabled", v)}
            />
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="celebration_enabled">Celebration animation</Label>
            <Switch
              id="celebration_enabled"
              checked={settings?.celebration_enabled ?? true}
              onCheckedChange={(v) => handleToggle("celebration_enabled", v)}
            />
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
