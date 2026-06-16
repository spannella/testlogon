import { Plus, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { QuoteLineItemIn } from "@/api/endpoints/quotes";
import { centsToDollarsInput, formatCents, parseDollarsToCents } from "./quotesUtils";

export interface DraftLineItem {
  description: string;
  qty: number;
  unitPriceInput: string;
  discountPct: number;
  taxPct: number;
}

export function emptyLineItem(): DraftLineItem {
  return { description: "", qty: 1, unitPriceInput: "0.00", discountPct: 0, taxPct: 0 };
}

export function draftToApi(d: DraftLineItem): QuoteLineItemIn {
  return {
    description: d.description.trim(),
    qty: Math.max(1, Math.floor(d.qty || 1)),
    unit_price_cents: parseDollarsToCents(d.unitPriceInput),
    discount_bps: Math.round((d.discountPct || 0) * 100),
    tax_rate_bps: Math.round((d.taxPct || 0) * 100),
  };
}

export function lineItemTotals(items: DraftLineItem[], currency: string) {
  let subtotal = 0;
  let discount = 0;
  let tax = 0;
  for (const it of items) {
    const unit = parseDollarsToCents(it.unitPriceInput);
    const gross = unit * Math.max(1, Math.floor(it.qty || 1));
    const disc = Math.round((gross * Math.round((it.discountPct || 0) * 100)) / 10000);
    const taxable = gross - disc;
    const t = Math.round((taxable * Math.round((it.taxPct || 0) * 100)) / 10000);
    subtotal += gross;
    discount += disc;
    tax += t;
  }
  const total = subtotal - discount + tax;
  return {
    subtotal,
    discount,
    tax,
    total,
    fmt: {
      subtotal: formatCents(subtotal, currency),
      discount: formatCents(discount, currency),
      tax: formatCents(tax, currency),
      total: formatCents(total, currency),
    },
  };
}

function rowTotal(it: DraftLineItem, currency: string): string {
  const unit = parseDollarsToCents(it.unitPriceInput);
  const gross = unit * Math.max(1, Math.floor(it.qty || 1));
  const disc = Math.round((gross * Math.round((it.discountPct || 0) * 100)) / 10000);
  const taxable = gross - disc;
  const t = Math.round((taxable * Math.round((it.taxPct || 0) * 100)) / 10000);
  return formatCents(taxable + t, currency);
}

interface LineItemEditorProps {
  items: DraftLineItem[];
  currency: string;
  onChange: (items: DraftLineItem[]) => void;
}

export function LineItemEditor({ items, currency, onChange }: LineItemEditorProps) {
  const update = (idx: number, patch: Partial<DraftLineItem>) => {
    onChange(items.map((it, i) => (i === idx ? { ...it, ...patch } : it)));
  };
  const remove = (idx: number) => {
    onChange(items.filter((_, i) => i !== idx));
  };
  const add = () => onChange([...items, emptyLineItem()]);

  const totals = lineItemTotals(items, currency);

  return (
    <div className="space-y-3">
      <div className="overflow-x-auto rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="min-w-[200px]">Description</TableHead>
              <TableHead className="w-20">Qty</TableHead>
              <TableHead className="w-32">Unit price</TableHead>
              <TableHead className="w-24">Disc %</TableHead>
              <TableHead className="w-24">Tax %</TableHead>
              <TableHead className="w-32 text-right">Line total</TableHead>
              <TableHead className="w-12" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.length === 0 && (
              <TableRow>
                <TableCell colSpan={7} className="text-center text-sm text-muted-foreground">
                  No line items yet. Add one below.
                </TableCell>
              </TableRow>
            )}
            {items.map((it, idx) => (
              <TableRow key={idx}>
                <TableCell>
                  <Input
                    aria-label={`Line ${idx + 1} description`}
                    value={it.description}
                    onChange={(e) => update(idx, { description: e.target.value })}
                    placeholder="Item description"
                  />
                </TableCell>
                <TableCell>
                  <Input
                    type="number"
                    min={1}
                    aria-label={`Line ${idx + 1} quantity`}
                    value={it.qty}
                    onChange={(e) => update(idx, { qty: Number(e.target.value) })}
                  />
                </TableCell>
                <TableCell>
                  <Input
                    inputMode="decimal"
                    aria-label={`Line ${idx + 1} unit price`}
                    value={it.unitPriceInput}
                    onChange={(e) => update(idx, { unitPriceInput: e.target.value })}
                    onBlur={(e) =>
                      update(idx, {
                        unitPriceInput: centsToDollarsInput(parseDollarsToCents(e.target.value)),
                      })
                    }
                  />
                </TableCell>
                <TableCell>
                  <Input
                    type="number"
                    min={0}
                    max={100}
                    aria-label={`Line ${idx + 1} discount percent`}
                    value={it.discountPct}
                    onChange={(e) => update(idx, { discountPct: Number(e.target.value) })}
                  />
                </TableCell>
                <TableCell>
                  <Input
                    type="number"
                    min={0}
                    max={100}
                    aria-label={`Line ${idx + 1} tax percent`}
                    value={it.taxPct}
                    onChange={(e) => update(idx, { taxPct: Number(e.target.value) })}
                  />
                </TableCell>
                <TableCell className="text-right font-medium tabular-nums">
                  {rowTotal(it, currency)}
                </TableCell>
                <TableCell>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    aria-label={`Remove line ${idx + 1}`}
                    onClick={() => remove(idx)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <Button type="button" variant="outline" size="sm" onClick={add}>
        <Plus className="mr-1 h-4 w-4" /> Add line item
      </Button>

      <div className="flex justify-end">
        <div className="w-full max-w-xs space-y-1 text-sm">
          <div className="flex justify-between">
            <span className="text-muted-foreground">Subtotal</span>
            <span className="tabular-nums">{totals.fmt.subtotal}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Discount</span>
            <span className="tabular-nums">-{totals.fmt.discount}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Tax</span>
            <span className="tabular-nums">{totals.fmt.tax}</span>
          </div>
          <div className="flex justify-between border-t pt-1 text-base font-semibold">
            <Label>Total</Label>
            <span className="tabular-nums">{totals.fmt.total}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
