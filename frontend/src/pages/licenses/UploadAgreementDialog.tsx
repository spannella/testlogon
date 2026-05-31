import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  createLicenseAgreement,
  LICENSE_TYPES,
} from "@/api/endpoints/licenseAgreements";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface Props {
  onCreated: () => void;
}

export function UploadAgreementDialog({ onCreated }: Props) {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [licensorName, setLicensorName] = useState("");
  const [licenseType, setLicenseType] = useState<string>("royalty_free");
  const [territory, setTerritory] = useState("worldwide");
  const [expiresAt, setExpiresAt] = useState("");
  const [notes, setNotes] = useState("");
  const [file, setFile] = useState<File | null>(null);

  const reset = () => {
    setTitle("");
    setLicensorName("");
    setLicenseType("royalty_free");
    setTerritory("worldwide");
    setExpiresAt("");
    setNotes("");
    setFile(null);
  };

  const createMut = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error("Please select a file");
      const expiresTs = expiresAt
        ? Math.floor(new Date(expiresAt).getTime() / 1000)
        : null;
      return createLicenseAgreement({
        title: title.trim(),
        licensor_name: licensorName.trim(),
        license_type: licenseType,
        territory: territory.trim() || "worldwide",
        expires_at: expiresTs,
        notes: notes.trim(),
        file,
      });
    },
    onSuccess: () => {
      toast.success("Agreement uploaded — pending review");
      reset();
      setOpen(false);
      onCreated();
    },
    onError: (e: Error) => toast.error(e.message || "Upload failed"),
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>Upload Agreement</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Upload License Agreement</DialogTitle>
          <DialogDescription>
            Upload a PDF or image (max 20 MB) proving your rights to third-party
            content.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1">
            <Label htmlFor="la-title">Title</Label>
            <Input
              id="la-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Epidemic Sound - Royalty Free Music Pack"
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="la-licensor">Licensor</Label>
            <Input
              id="la-licensor"
              value={licensorName}
              onChange={(e) => setLicensorName(e.target.value)}
              placeholder="Epidemic Sound AB"
            />
          </div>
          <div className="space-y-1">
            <Label>License type</Label>
            <Select value={licenseType} onValueChange={setLicenseType}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {LICENSE_TYPES.map((t) => (
                  <SelectItem key={t} value={t}>
                    {t.replace(/_/g, " ")}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="la-territory">Territory</Label>
            <Input
              id="la-territory"
              value={territory}
              onChange={(e) => setTerritory(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="la-expires">Expiry date (optional)</Label>
            <Input
              id="la-expires"
              type="date"
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="la-notes">Notes</Label>
            <Textarea
              id="la-notes"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="la-file">Document</Label>
            <Input
              id="la-file"
              type="file"
              accept="application/pdf,image/png,image/jpeg,image/webp"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </div>
        </div>
        <DialogFooter>
          <Button
            onClick={() => createMut.mutate()}
            disabled={
              createMut.isPending ||
              !title.trim() ||
              !licensorName.trim() ||
              !file
            }
          >
            {createMut.isPending ? "Uploading…" : "Upload"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
