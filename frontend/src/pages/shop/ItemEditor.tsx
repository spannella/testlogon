import { useEffect, useState } from "react";
import { Loader2, Upload, X } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  createCatalogItem,
  updateCatalogItem,
  uploadItemImage,
} from "@/api/endpoints/cart";
import type { CatalogItem } from "@/api/types";

interface ItemEditorProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  categoryId: string;
  /** If provided, we are editing; otherwise creating */
  item?: CatalogItem;
  onSaved: () => void;
}

interface AttrRow {
  key: string;
  value: string;
}

export function ItemEditor({
  open,
  onOpenChange,
  categoryId,
  item,
  onSaved,
}: ItemEditorProps) {
  const isEdit = !!item;

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [priceDollars, setPriceDollars] = useState("");
  const [currency, setCurrency] = useState("USD");
  const [attrs, setAttrs] = useState<AttrRow[]>([]);
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // Pre-fill form when editing
  useEffect(() => {
    if (open && item) {
      setName(item.name);
      setDescription(item.description ?? "");
      setPriceDollars((item.price_cents / 100).toFixed(2));
      setCurrency(item.currency);
      const entries = Object.entries(item.attributes ?? {});
      setAttrs(
        entries.length > 0
          ? entries.map(([k, v]) => ({ key: k, value: String(v) }))
          : [{ key: "", value: "" }],
      );
      setImageFile(null);
      setImagePreview(null);
    } else if (open) {
      setName("");
      setDescription("");
      setPriceDollars("");
      setCurrency("USD");
      setAttrs([{ key: "", value: "" }]);
      setImageFile(null);
      setImagePreview(null);
    }
  }, [open, item]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImageFile(file);
    const reader = new FileReader();
    reader.onload = (ev) => setImagePreview(ev.target?.result as string);
    reader.readAsDataURL(file);
  };

  const updateAttr = (idx: number, field: "key" | "value", val: string) => {
    setAttrs((prev) => prev.map((r, i) => (i === idx ? { ...r, [field]: val } : r)));
  };

  const addAttr = () => setAttrs((prev) => [...prev, { key: "", value: "" }]);

  const removeAttr = (idx: number) =>
    setAttrs((prev) => prev.filter((_, i) => i !== idx));

  const handleSave = async () => {
    if (!name.trim()) {
      toast.error("Name is required");
      return;
    }
    const priceCents = Math.round(parseFloat(priceDollars || "0") * 100);
    if (isNaN(priceCents) || priceCents < 0) {
      toast.error("Invalid price");
      return;
    }

    const attributes: Record<string, string> = {};
    for (const row of attrs) {
      const k = row.key.trim();
      if (k) attributes[k] = row.value;
    }

    setSaving(true);
    try {
      let saved: CatalogItem;
      if (isEdit && item) {
        saved = await updateCatalogItem(categoryId, item.item_id, {
          name: name.trim(),
          description: description.trim() || undefined,
          price_cents: priceCents,
          currency,
          attributes,
        });
      } else {
        saved = await createCatalogItem(categoryId, {
          name: name.trim(),
          description: description.trim() || undefined,
          price_cents: priceCents,
          currency,
          image_urls: [],
          attributes,
        });
      }

      // Upload image if provided
      if (imageFile) {
        await uploadItemImage(categoryId, saved.item_id, imageFile);
      }

      toast.success(isEdit ? "Item updated" : "Item created");
      onOpenChange(false);
      onSaved();
    } catch {
      toast.error(isEdit ? "Failed to update item" : "Failed to create item");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-lg overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit Item" : "New Item"}</DialogTitle>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-1">
            <Label htmlFor="item-name">Name</Label>
            <Input
              id="item-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Product name"
            />
          </div>

          <div className="space-y-1">
            <Label htmlFor="item-desc">Description</Label>
            <Textarea
              id="item-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional description"
              rows={3}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <Label htmlFor="item-price">Price</Label>
              <Input
                id="item-price"
                type="number"
                step="0.01"
                min="0"
                value={priceDollars}
                onChange={(e) => setPriceDollars(e.target.value)}
                placeholder="0.00"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="item-currency">Currency</Label>
              <Input
                id="item-currency"
                value={currency}
                onChange={(e) => setCurrency(e.target.value.toUpperCase())}
                maxLength={3}
                placeholder="USD"
              />
            </div>
          </div>

          {/* Attributes */}
          <div className="space-y-2">
            <Label>Attributes</Label>
            {attrs.map((row, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <Input
                  placeholder="Key"
                  value={row.key}
                  onChange={(e) => updateAttr(idx, "key", e.target.value)}
                  className="flex-1"
                />
                <Input
                  placeholder="Value"
                  value={row.value}
                  onChange={(e) => updateAttr(idx, "value", e.target.value)}
                  className="flex-1"
                />
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 shrink-0"
                  onClick={() => removeAttr(idx)}
                >
                  <X className="h-3.5 w-3.5" />
                </Button>
              </div>
            ))}
            <Button variant="outline" size="sm" onClick={addAttr}>
              Add attribute
            </Button>
          </div>

          {/* Image upload */}
          <div className="space-y-2">
            <Label>Image</Label>
            {imagePreview && (
              <img
                src={imagePreview}
                alt="Preview"
                className="h-32 w-full rounded-md border object-contain"
              />
            )}
            <label className="flex cursor-pointer items-center gap-2 rounded-md border border-dashed px-3 py-2 text-sm text-muted-foreground hover:bg-accent">
              <Upload className="h-4 w-4" />
              {imageFile ? imageFile.name : "Choose image..."}
              <input
                type="file"
                accept="image/*"
                className="hidden"
                onChange={handleFileChange}
              />
            </label>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={saving}>
            {saving && <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />}
            {isEdit ? "Save Changes" : "Create Item"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
