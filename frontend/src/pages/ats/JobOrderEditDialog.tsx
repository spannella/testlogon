/**
 * Dialog for editing an existing Job Order.
 * Pre-populates all fields from the current job state.
 */
import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
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
import { ApiError } from "@/api/client";
import {
  updateJobOrder,
  type JobOrder,
  type JobOrderType,
  JOB_ORDER_TYPES,
} from "@/api/endpoints/jobOrders";

interface Props {
  job: JobOrder;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onUpdated?: (job: JobOrder) => void;
}

function typeLabel(t: string) {
  switch (t) {
    case "hire":
      return "Direct Hire";
    case "contract":
      return "Contract";
    case "contract_to_hire":
      return "Contract-to-Hire";
    case "referral":
      return "Referral";
    default:
      return t;
  }
}

/** Convert integer cents to display string like "75.00" */
function centsToDisplay(cents: number | null | undefined): string {
  if (cents == null) return "";
  return (cents / 100).toFixed(2);
}

export function JobOrderEditDialog({ job, open, onOpenChange, onUpdated }: Props) {
  const queryClient = useQueryClient();

  const [title, setTitle] = useState(job.title);
  const [type, setType] = useState<JobOrderType>(job.type);
  const [openings, setOpenings] = useState(String(job.openings));
  const [clientContactId, setClientContactId] = useState(job.client_contact_id ?? "");
  const [payRateDisplay, setPayRateDisplay] = useState(centsToDisplay(job.pay_rate_cents));
  const [billRateDisplay, setBillRateDisplay] = useState(centsToDisplay(job.bill_rate_cents));
  const [duration, setDuration] = useState(job.duration ?? "");
  const [city, setCity] = useState(job.city ?? "");
  const [state, setState] = useState(job.state ?? "");
  const [description, setDescription] = useState(job.description ?? "");
  const [hot, setHot] = useState(job.hot);

  // Sync when the job prop changes (e.g., re-open dialog after refresh)
  useEffect(() => {
    setTitle(job.title);
    setType(job.type);
    setOpenings(String(job.openings));
    setClientContactId(job.client_contact_id ?? "");
    setPayRateDisplay(centsToDisplay(job.pay_rate_cents));
    setBillRateDisplay(centsToDisplay(job.bill_rate_cents));
    setDuration(job.duration ?? "");
    setCity(job.city ?? "");
    setState(job.state ?? "");
    setDescription(job.description ?? "");
    setHot(job.hot);
  }, [job]);

  const updateMut = useMutation({
    mutationFn: () =>
      updateJobOrder(job.job_id, {
        title: title.trim(),
        type,
        openings: parseInt(openings, 10) || 0,
        client_contact_id: clientContactId.trim() || null,
        pay_rate_cents: payRateDisplay
          ? Math.round(parseFloat(payRateDisplay) * 100)
          : null,
        bill_rate_cents: billRateDisplay
          ? Math.round(parseFloat(billRateDisplay) * 100)
          : null,
        duration: duration.trim() || null,
        city: city.trim() || null,
        state: state.trim() || null,
        description: description.trim() || null,
        hot,
      }),
    onSuccess: (updated) => {
      toast.success("Job order updated");
      void queryClient.invalidateQueries({ queryKey: ["ats", "jobs"] });
      onUpdated?.(updated);
      onOpenChange(false);
    },
    onError: (err: unknown) => {
      const msg = err instanceof ApiError ? err.detail : "Failed to update job order";
      toast.error(msg);
    },
  });

  const canSubmit = title.trim().length >= 1 && !updateMut.isPending;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Edit Job Order</DialogTitle>
          <DialogDescription>
            Update details for <span className="font-medium">{job.title}</span>
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          {/* Title */}
          <div className="space-y-1">
            <Label htmlFor="ejo-title">Title</Label>
            <Input
              id="ejo-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              data-testid="ejo-title"
            />
          </div>

          {/* Type */}
          <div className="space-y-1">
            <Label htmlFor="ejo-type">Type</Label>
            <Select
              value={type}
              onValueChange={(v) => setType(v as JobOrderType)}
            >
              <SelectTrigger id="ejo-type" data-testid="ejo-type">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {JOB_ORDER_TYPES.map((t) => (
                  <SelectItem key={t} value={t}>
                    {typeLabel(t)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Openings */}
          <div className="space-y-1">
            <Label htmlFor="ejo-openings">Openings</Label>
            <Input
              id="ejo-openings"
              type="number"
              min={0}
              max={10000}
              value={openings}
              onChange={(e) => setOpenings(e.target.value)}
              data-testid="ejo-openings"
            />
          </div>

          {/* Client Contact */}
          <div className="space-y-1">
            <Label htmlFor="ejo-contact">Client Contact ID</Label>
            <Input
              id="ejo-contact"
              value={clientContactId}
              onChange={(e) => setClientContactId(e.target.value)}
              placeholder="contact-id (optional)"
              data-testid="ejo-contact"
            />
          </div>

          {/* Pay + Bill rates */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="ejo-pay-rate">Pay Rate ($/hr)</Label>
              <Input
                id="ejo-pay-rate"
                type="number"
                min={0}
                step={0.01}
                value={payRateDisplay}
                onChange={(e) => setPayRateDisplay(e.target.value)}
                data-testid="ejo-pay-rate"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="ejo-bill-rate">Bill Rate ($/hr)</Label>
              <Input
                id="ejo-bill-rate"
                type="number"
                min={0}
                step={0.01}
                value={billRateDisplay}
                onChange={(e) => setBillRateDisplay(e.target.value)}
                data-testid="ejo-bill-rate"
              />
            </div>
          </div>

          {/* Location */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="ejo-city">City</Label>
              <Input
                id="ejo-city"
                value={city}
                onChange={(e) => setCity(e.target.value)}
                data-testid="ejo-city"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="ejo-state">State</Label>
              <Input
                id="ejo-state"
                value={state}
                onChange={(e) => setState(e.target.value)}
                data-testid="ejo-state"
              />
            </div>
          </div>

          {/* Duration */}
          <div className="space-y-1">
            <Label htmlFor="ejo-duration">Duration</Label>
            <Input
              id="ejo-duration"
              value={duration}
              onChange={(e) => setDuration(e.target.value)}
              placeholder="6 months / permanent"
              data-testid="ejo-duration"
            />
          </div>

          {/* Hot */}
          <div className="flex items-center gap-2">
            <input
              id="ejo-hot"
              type="checkbox"
              checked={hot}
              onChange={(e) => setHot(e.target.checked)}
              className="h-4 w-4 accent-primary"
              data-testid="ejo-hot"
            />
            <Label htmlFor="ejo-hot" className="cursor-pointer">
              Mark as Hot
            </Label>
          </div>

          {/* Description */}
          <div className="space-y-1">
            <Label htmlFor="ejo-description">Description</Label>
            <Textarea
              id="ejo-description"
              rows={5}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              data-testid="ejo-description"
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => updateMut.mutate()}
            disabled={!canSubmit}
            data-testid="ejo-submit"
          >
            {updateMut.isPending ? "Saving…" : "Save Changes"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
