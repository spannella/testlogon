import React from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Copy, Check, Link2 } from "lucide-react";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectTrigger,
  SelectContent,
  SelectItem,
  SelectValue,
} from "@/components/ui/select";
import { createShareLink } from "@/api/endpoints/fileShareLinks";
import type { FileEntry, ShareLink } from "@/api/types";

const EXPIRY_OPTIONS: { value: string; label: string }[] = [
  { value: "1", label: "1 hour" },
  { value: "6", label: "6 hours" },
  { value: "24", label: "24 hours" },
  { value: "168", label: "7 days" },
  { value: "720", label: "30 days" },
];

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  file: FileEntry;
}

export function ShareLinkDialog({ open, onOpenChange, file }: Props) {
  const qc = useQueryClient();
  const [expiryHours, setExpiryHours] = React.useState("24");
  const [maxDownloads, setMaxDownloads] = React.useState("1");
  const [password, setPassword] = React.useState("");
  const [created, setCreated] = React.useState<ShareLink | null>(null);
  const [copied, setCopied] = React.useState(false);

  React.useEffect(() => {
    if (open) {
      setExpiryHours("24");
      setMaxDownloads("1");
      setPassword("");
      setCreated(null);
      setCopied(false);
    }
  }, [open]);

  const createMut = useMutation({
    mutationFn: () =>
      createShareLink({
        file_node_id: file.path,
        expiry_hours: Number(expiryHours),
        max_downloads: Math.max(1, Number(maxDownloads) || 1),
        password: password.trim().length >= 4 ? password.trim() : undefined,
      }),
    onSuccess: (link) => {
      setCreated(link);
      qc.invalidateQueries({ queryKey: ["share-links"] });
      toast.success("Share link created");
    },
    onError: () => toast.error("Failed to create share link"),
  });

  const copy = async () => {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.share_url);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error("Copy failed");
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent data-testid="share-link-dialog">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Link2 className="h-4 w-4" /> Create Share Link
          </DialogTitle>
          <DialogDescription>
            Generate an encrypted, time-limited download link for{" "}
            <span className="font-medium">{file.name}</span>.
          </DialogDescription>
        </DialogHeader>

        {!created ? (
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="sl-expiry">Expires after</Label>
              <Select value={expiryHours} onValueChange={setExpiryHours}>
                <SelectTrigger id="sl-expiry" data-testid="share-link-expiry">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {EXPIRY_OPTIONS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="sl-max">Maximum downloads</Label>
              <Input
                id="sl-max"
                type="number"
                min={1}
                max={100}
                value={maxDownloads}
                onChange={(e) => setMaxDownloads(e.target.value)}
                data-testid="share-link-max-downloads"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="sl-pass">Password (optional)</Label>
              <Input
                id="sl-pass"
                type="password"
                placeholder="At least 4 characters"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                data-testid="share-link-password"
              />
            </div>
          </div>
        ) : (
          <div className="space-y-2">
            <Label>Shareable link</Label>
            <div className="flex items-center gap-2">
              <Input
                readOnly
                value={created.share_url}
                data-testid="share-link-url"
                onFocus={(e) => e.currentTarget.select()}
              />
              <Button
                type="button"
                variant="outline"
                size="icon"
                onClick={copy}
                data-testid="share-link-copy"
                aria-label="Copy link"
              >
                {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              </Button>
            </div>
            <p className="text-sm text-muted-foreground">
              {created.has_password ? "Password protected. " : ""}
              Valid for {created.max_downloads} download
              {created.max_downloads === 1 ? "" : "s"}.
            </p>
          </div>
        )}

        <DialogFooter>
          {!created ? (
            <Button
              type="button"
              onClick={() => createMut.mutate()}
              disabled={createMut.isPending}
              data-testid="share-link-submit"
            >
              {createMut.isPending ? "Creating…" : "Create link"}
            </Button>
          ) : (
            <Button type="button" onClick={() => onOpenChange(false)}>
              Done
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default ShareLinkDialog;
