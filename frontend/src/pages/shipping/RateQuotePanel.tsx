import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { Calculator } from "lucide-react";

import {
  estimateRates,
  type CarrierCode,
  type MethodCode,
  type ShippingRateQuote,
} from "@/api/endpoints/shipping";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { CARRIER_CODES, METHOD_CODES, fmtCents } from "./shippingHelpers";

export function RateQuotePanel() {
  const [carrierCode, setCarrierCode] = useState<CarrierCode>("ups");
  const [methodCode, setMethodCode] = useState<MethodCode>("ground");
  const [weightOz, setWeightOz] = useState("16");
  const [destZip, setDestZip] = useState("");
  const [originZip, setOriginZip] = useState("");
  const [quote, setQuote] = useState<ShippingRateQuote | null>(null);

  const quoteMut = useMutation({
    mutationFn: () =>
      estimateRates({
        carrier_code: carrierCode,
        method_code: methodCode,
        weight_oz: Number(weightOz) || 0,
        destination_zip: destZip.trim() || "00000",
        origin_zip: originZip.trim() || undefined,
      }),
    onSuccess: (q) => {
      setQuote(q);
      if (q.options.length === 0) {
        toast.info("No matching enabled methods for that carrier/method.");
      }
    },
    onError: (e: unknown) =>
      toast.error(e instanceof Error ? e.message : "Unable to estimate rate"),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Rate quote</CardTitle>
        <CardDescription>
          Estimate shipping cost for a carrier, method, and parcel weight.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div className="grid gap-1.5">
            <Label>Carrier</Label>
            <Select value={carrierCode} onValueChange={(v) => setCarrierCode(v as CarrierCode)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {CARRIER_CODES.map((c) => (
                  <SelectItem key={c} value={c}>
                    {c}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-1.5">
            <Label>Method</Label>
            <Select value={methodCode} onValueChange={(v) => setMethodCode(v as MethodCode)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {METHOD_CODES.map((c) => (
                  <SelectItem key={c} value={c}>
                    {c}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-1.5">
            <Label>Weight (oz)</Label>
            <Input
              type="number"
              min="0"
              value={weightOz}
              onChange={(e) => setWeightOz(e.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label>Destination ZIP</Label>
            <Input
              value={destZip}
              placeholder="94105"
              onChange={(e) => setDestZip(e.target.value)}
            />
          </div>
          <div className="grid gap-1.5">
            <Label>Origin ZIP (optional)</Label>
            <Input
              value={originZip}
              placeholder="10001"
              onChange={(e) => setOriginZip(e.target.value)}
            />
          </div>
          <div className="flex items-end">
            <Button
              className="w-full"
              disabled={quoteMut.isPending}
              onClick={() => quoteMut.mutate()}
            >
              <Calculator className="mr-1 h-4 w-4" />
              {quoteMut.isPending ? "Estimating…" : "Get quote"}
            </Button>
          </div>
        </div>

        {quote && (
          <div className="space-y-2">
            <div className="text-xs text-muted-foreground">
              Quote {quote.request_id} · {new Date(quote.generated_at * 1000).toLocaleString()}
            </div>
            {quote.options.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No rate options available.
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Carrier</TableHead>
                    <TableHead>Method</TableHead>
                    <TableHead>Rate</TableHead>
                    <TableHead>Transit</TableHead>
                    <TableHead>Est. delivery</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {quote.options.map((o, i) => (
                    <TableRow key={`${o.carrier_code}-${o.method_code}-${i}`}>
                      <TableCell className="uppercase">{o.carrier_code}</TableCell>
                      <TableCell>{o.method_code}</TableCell>
                      <TableCell className="font-medium">
                        {fmtCents(o.rate_cents, o.currency)}
                      </TableCell>
                      <TableCell>
                        {o.transit_days_min != null && o.transit_days_max != null
                          ? `${o.transit_days_min}–${o.transit_days_max} days`
                          : "—"}
                      </TableCell>
                      <TableCell>{o.estimated_delivery ?? "—"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
