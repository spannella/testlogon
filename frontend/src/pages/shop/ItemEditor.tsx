import { useEffect, useState } from "react";
import { Loader2, X } from "lucide-react";
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  createCatalogItem,
  updateCatalogItem,
} from "@/api/endpoints/cart";
import { uploadPostImage } from "@/api/endpoints/newsfeed";
import type { CatalogItem } from "@/api/types";

const CURRENCIES = ["USD", "EUR", "GBP", "CAD", "AUD", "JPY", "CHF", "CNY", "INR", "MXN", "BRL", "SGD", "HKD", "NOK", "SEK", "DKK", "NZD", "ZAR", "KRW", "AED"];

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
  const [imageUrls, setImageUrls] = useState<string[]>([]);
  const [stockCount, setStockCount] = useState("");
  const [lowStockThreshold, setLowStockThreshold] = useState("5");
  const [uploading, setUploading] = useState(false);
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
      setImageUrls(item.image_urls ?? []);
      setStockCount(item.stock_count != null ? String(item.stock_count) : "");
      setLowStockThreshold(String(item.low_stock_threshold ?? 5));
    } else if (open) {
      setName("");
      setDescription("");
      setPriceDollars("");
      setCurrency("USD");
      setAttrs([{ key: "", value: "" }]);
      setImageUrls([]);
      setStockCount("");
      setLowStockThreshold("5");
    }
  }, [open, item]);

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    if (!file.type.startsWith("image/")) {
      toast.error("Please select an image file");
      return;
    }
    setUploading(true);
    try {
      const result = await uploadPostImage(file);
      setImageUrls((prev) => [...prev, result.url]);
    } catch {
      toast.error("Failed to upload image");
    } finally {
      setUploading(false);
    }
  };

  const removeImage = (idx: number) =>
    setImageUrls((prev) => prev.filter((_, i) => i !== idx));

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

    const parsedStock = stockCount.trim() === "" ? undefined : parseInt(stockCount, 10);
    const parsedThreshold = lowStockThreshold.trim() === "" ? undefined : parseInt(lowStockThreshold, 10);

    setSaving(true);
    try {
      if (isEdit && item) {
        await updateCatalogItem(categoryId, item.item_id, {
          name: name.trim(),
          description: description.trim() || undefined,
          price_cents: priceCents,
          currency,
          image_urls: imageUrls,
          attributes,
          stock_count: parsedStock != null && !isNaN(parsedStock) ? parsedStock : undefined,
          low_stock_threshold: parsedThreshold != null && !isNaN(parsedThreshold) ? parsedThreshold : undefined,
        });
      } else {
        await createCatalogItem(categoryId, {
          name: name.trim(),
          description: description.trim() || undefined,
          price_cents: priceCents,
          currency,
          image_urls: imageUrls,
          attributes,
          stock_count: parsedStock != null && !isNaN(parsedStock) ? parsedStock : undefined,
          low_stock_threshold: parsedThreshold != null && !isNaN(parsedThreshold) ? parsedThreshold : undefined,
        });
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
              <Select value={currency} onValueChange={setCurrency}>
                <SelectTrigger id="item-currency">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {CURRENCIES.map((c) => (
                    <SelectItem key={c} value={c}>{c}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Stock Management */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <Label htmlFor="item-stock">Stock Quantity</Label>
              <Input
                id="item-stock"
                type="number"
                min="0"
                value={stockCount}
                onChange={(e) => setStockCount(e.target.value)}
                placeholder="Unlimited"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="item-threshold">Low Stock Alert At</Label>
              <Input
                id="item-threshold"
                type="number"
                min="0"
                value={lowStockThreshold}
                onChange={(e) => setLowStockThreshold(e.target.value)}
                placeholder="5"
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

          {/* Images */}
          <div className="space-y-2">
            <Label>Images</Label>
            {imageUrls.length > 0 && (
              <div className="grid grid-cols-3 gap-2">
                {imageUrls.map((url, idx) => (
                  <div key={idx} className="relative">
                    <img
                      src={url}
                      alt={`Image ${idx + 1}`}
                      className="h-24 w-full rounded-md border object-cover"
                    />
                    <button
                      type="button"
                      onClick={() => removeImage(idx)}
                      className="absolute right-1 top-1 flex h-5 w-5 items-center justify-center rounded-full bg-black/60 text-white hover:bg-black/80"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            )}
            <label className="flex cursor-pointer items-center gap-2 rounded-md border border-dashed px-3 py-2 text-sm text-muted-foreground hover:bg-accent">
              {uploading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Uploading…
                </>
              ) : (
                <>
                  + Add image
                </>
              )}
              <input
                type="file"
                accept="image/*"
                className="hidden"
                onChange={handleFileChange}
                disabled={uploading}
              />
            </label>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving || uploading}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={saving || uploading}>
            {saving && <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />}
            {isEdit ? "Save Changes" : "Create Item"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
