/**
 * Dialog for creating a new Job Order.
 * Used by JobOrdersPage and JobOrderDetailPage (edit mode uses a separate dialog).
 */
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
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
  createJobOrder,
  type JobOrder,
  type JobOrderCreateInput,
  type JobOrderType,
  type JobOrderStatus,
  JOB_ORDER_TYPES,
  JOB_ORDER_STATUSES,
} from "@/api/endpoints/jobOrders";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated?: (job: JobOrder) => void;
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

export function JobOrderCreateDialog({ open, onOpenChange, onCreated }: Props) {
  const [title, setTitle] = useState("");
  const [type, setType] = useState<JobOrderType>("hire");
  const [status, setStatus] = useState<JobOrderStatus>("active");
  const [openings, setOpenings] = useState("1");
  const [clientCompanyId, setClientCompanyId] = useState("");
  const [clientContactId, setClientContactId] = useState("");
  const [payRateCents, setPayRateCents] = useState("");
  const [billRateCents, setBillRateCents] = useState("");
  const [duration, setDuration] = useState("");
  const [city, setCity] = useState("");
  const [state, setState] = useState("");
  const [description, setDescription] = useState("");
  const [hot, setHot] = useState(false);

  const createMut = useMutation({
    mutationFn: () => {
      const body: JobOrderCreateInput = {
        title: title.trim(),
        type,
        status,
        openings: parseInt(openings, 10) || 1,
        client_company_id: clientCompanyId.trim(),
        client_contact_id: clientContactId.trim() || null,
        recruiter_subs: [],
        hot,
        public: false,
        pay_rate_cents: payRateCents ? Math.round(parseFloat(payRateCents) * 100) : null,
        bill_rate_cents: billRateCents ? Math.round(parseFloat(billRateCents) * 100) : null,
        duration: duration.trim() || null,
        city: city.trim() || null,
        state: state.trim() || null,
        description: description.trim() || null,
      };
      return createJobOrder(body);
    },
    onSuccess: (job) => {
      onCreated?.(job);
      onOpenChange(false);
      resetForm();
    },
    onError: (err: unknown) => {
      const msg =
        err instanceof ApiError ? err.detail : "Failed to create job order";
      toast.error(msg);
    },
  });

  function resetForm() {
    setTitle("");
    setType("hire");
    setStatus("active");
    setOpenings("1");
    setClientCompanyId("");
    setClientContactId("");
    setPayRateCents("");
    setBillRateCents("");
    setDuration("");
    setCity("");
    setState("");
    setDescription("");
    setHot(false);
  }

  const canSubmit =
    title.trim().length >= 1 &&
    clientCompanyId.trim().length >= 1 &&
    !createMut.isPending;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>New Job Order</DialogTitle>
          <DialogDescription>
            Create a new recruiting requisition for a client.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          {/* Title */}
          <div className="space-y-1">
            <Label htmlFor="jo-title">
              Title <span className="text-destructive">*</span>
            </Label>
            <Input
              id="jo-title"
              placeholder="Senior Software Engineer"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              data-testid="jo-title"
            />
          </div>

          {/* Type + Status */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="jo-type">Type</Label>
              <Select
                value={type}
                onValueChange={(v) => setType(v as JobOrderType)}
              >
                <SelectTrigger id="jo-type" data-testid="jo-type">
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
            <div className="space-y-1">
              <Label htmlFor="jo-status">Initial Status</Label>
              <Select
                value={status}
                onValueChange={(v) => setStatus(v as JobOrderStatus)}
              >
                <SelectTrigger id="jo-status" data-testid="jo-status">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {JOB_ORDER_STATUSES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s.replace("_", " ")}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Client Company */}
          <div className="space-y-1">
            <Label htmlFor="jo-company">
              Client Company ID <span className="text-destructive">*</span>
            </Label>
            <Input
              id="jo-company"
              placeholder="acme-corp"
              value={clientCompanyId}
              onChange={(e) => setClientCompanyId(e.target.value)}
              data-testid="jo-company"
            />
          </div>

          {/* Client Contact */}
          <div className="space-y-1">
            <Label htmlFor="jo-contact">Client Contact ID</Label>
            <Input
              id="jo-contact"
              placeholder="contact-id (optional)"
              value={clientContactId}
              onChange={(e) => setClientContactId(e.target.value)}
              data-testid="jo-contact"
            />
          </div>

          {/* Openings */}
          <div className="space-y-1">
            <Label htmlFor="jo-openings">Openings</Label>
            <Input
              id="jo-openings"
              type="number"
              min={0}
              max={10000}
              value={openings}
              onChange={(e) => setOpenings(e.target.value)}
              data-testid="jo-openings"
            />
          </div>

          {/* Pay Rate + Bill Rate */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="jo-pay-rate">Pay Rate ($/hr)</Label>
              <Input
                id="jo-pay-rate"
                type="number"
                min={0}
                step={0.01}
                placeholder="75.00"
                value={payRateCents}
                onChange={(e) => setPayRateCents(e.target.value)}
                data-testid="jo-pay-rate"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="jo-bill-rate">Bill Rate ($/hr)</Label>
              <Input
                id="jo-bill-rate"
                type="number"
                min={0}
                step={0.01}
                placeholder="120.00"
                value={billRateCents}
                onChange={(e) => setBillRateCents(e.target.value)}
                data-testid="jo-bill-rate"
              />
            </div>
          </div>

          {/* Location */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="jo-city">City</Label>
              <Input
                id="jo-city"
                placeholder="San Francisco"
                value={city}
                onChange={(e) => setCity(e.target.value)}
                data-testid="jo-city"
              />
            </div>
            <div className="space-y-1">
              <Label htmlFor="jo-state">State</Label>
              <Input
                id="jo-state"
                placeholder="CA"
                value={state}
                onChange={(e) => setState(e.target.value)}
                data-testid="jo-state"
              />
            </div>
          </div>

          {/* Duration */}
          <div className="space-y-1">
            <Label htmlFor="jo-duration">Duration</Label>
            <Input
              id="jo-duration"
              placeholder="6 months / permanent"
              value={duration}
              onChange={(e) => setDuration(e.target.value)}
              data-testid="jo-duration"
            />
          </div>

          {/* Hot flag */}
          <div className="flex items-center gap-2">
            <input
              id="jo-hot"
              type="checkbox"
              checked={hot}
              onChange={(e) => setHot(e.target.checked)}
              className="h-4 w-4 accent-primary"
              data-testid="jo-hot"
            />
            <Label htmlFor="jo-hot" className="cursor-pointer">
              Mark as Hot (urgent fill)
            </Label>
          </div>

          {/* Description */}
          <div className="space-y-1">
            <Label htmlFor="jo-description">Description</Label>
            <Textarea
              id="jo-description"
              rows={4}
              placeholder="Job description, requirements, qualifications…"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              data-testid="jo-description"
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => createMut.mutate()}
            disabled={!canSubmit}
            data-testid="jo-submit"
          >
            {createMut.isPending ? "Creating…" : "Create Job Order"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
