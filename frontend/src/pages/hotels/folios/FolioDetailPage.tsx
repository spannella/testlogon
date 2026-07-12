/**
 * Hotel Guest Folio Detail (HTL-029..031).
 *
 * Route: hotels/folios/:hotelId/:rid
 *
 * Shows the full folio for a reservation: header summary, line-item charges,
 * payment history, deposit escrow status, balance due, and admin actions
 * (post charge, settle payment, take deposit, close folio).
 *
 * Feature-gated: HOTEL_PMS_ENABLED (default OFF) → backend returns 404.
 * Admin-only write actions are conditionally rendered based on role.
 */

import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  FileDown,
  ChevronLeft,
  Plus,
  CreditCard,
  Lock,
  X,
  AlertCircle,
  Loader2,
  RefreshCw,
  ReceiptText,
  Package,
} from "lucide-react";

import { ApiError } from "@/api/client";
import {
  getFolio,
  openFolio,
  addFolioLine,
  addFolioAddon,
  setFolioDepositPolicy,
  takeFolioDeposit,
  recordFolioPayment,
  closeFolio,
  folioPdfUrl,
  type FolioOut,
  type FolioLineOut,
  type FolioLineType,
  type FolioPaymentMethod,
  type DepositPolicyKind,
} from "@/api/endpoints/hotelFolios";
import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
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
import { Separator } from "@/components/ui/separator";
import { useAuthStore } from "@/stores/authStore";
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function centsToCurrency(cents: number, currency = "usd"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

const LINE_TYPE_LABELS: Record<FolioLineType, string> = {
  room_night:  "Room Night",
  addon:       "Add-on",
  tax:         "Tax",
  fee:         "Fee",
};

const LINE_TYPE_COLORS: Record<FolioLineType, string> = {
  room_night:  "bg-blue-100 text-blue-800",
  addon:       "bg-purple-100 text-purple-800",
  tax:         "bg-orange-100 text-orange-800",
  fee:         "bg-yellow-100 text-yellow-800",
};

const PAYMENT_METHOD_LABELS: Record<FolioPaymentMethod, string> = {
  wallet:            "Wallet",
  card_external:     "Card (External)",
  cash:              "Cash",
  check:             "Check",
  bank_transfer:     "Bank Transfer",
  deposit_applied:   "Deposit Applied",
};

// ─── Status badge ─────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "open"
      ? "bg-green-100 text-green-800"
      : "bg-gray-100 text-gray-600";
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium ${cls}`}>
      {status}
    </span>
  );
}

// ─── Line item row ────────────────────────────────────────────────────────────

function LineItemRow({
  line,
  currency,
}: {
  line: FolioLineOut;
  currency: string;
}) {
  const cls = LINE_TYPE_COLORS[line.line_type] ?? "bg-gray-100 text-gray-700";
  const label = LINE_TYPE_LABELS[line.line_type] ?? line.line_type;

  return (
    <div
      className="flex items-start justify-between gap-3 py-2.5 border-b last:border-0"
      data-testid={`folio-line-${line.line_id}`}
    >
      <div className="flex items-start gap-2 min-w-0">
        <span
          className={`mt-0.5 shrink-0 inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium ${cls}`}
        >
          {label}
        </span>
        <div className="min-w-0">
          <p className="text-sm font-medium truncate">{line.description}</p>
          {line.sku && (
            <p className="text-xs text-muted-foreground">SKU: {line.sku}</p>
          )}
          <p className="text-xs text-muted-foreground">
            {line.quantity} × {centsToCurrency(line.unit_price_cents, currency)}
          </p>
        </div>
      </div>
      <div className="text-sm font-semibold shrink-0">
        {centsToCurrency(line.amount_cents, currency)}
      </div>
    </div>
  );
}

// ─── Balance summary card ─────────────────────────────────────────────────────

function BalanceSummary({ folio }: { folio: FolioOut }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Balance Summary</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        <div className="flex justify-between">
          <span className="text-muted-foreground">Total charges</span>
          <span className="font-medium">
            {centsToCurrency(folio.charges_total_cents, folio.currency)}
          </span>
        </div>
        <div className="flex justify-between">
          <span className="text-muted-foreground">Payments received</span>
          <span className="font-medium text-green-700">
            − {centsToCurrency(folio.payments_total_cents, folio.currency)}
          </span>
        </div>
        {folio.deposit_held_cents > 0 && (
          <div className="flex justify-between">
            <span className="text-muted-foreground">Deposit held (escrow)</span>
            <span className="font-medium text-blue-700">
              − {centsToCurrency(folio.deposit_held_cents, folio.currency)}
            </span>
          </div>
        )}
        <Separator />
        <div className="flex justify-between font-semibold">
          <span>Balance due</span>
          <span
            className={
              folio.balance_due_cents > 0 ? "text-red-600" : "text-green-700"
            }
          >
            {centsToCurrency(folio.balance_due_cents, folio.currency)}
          </span>
        </div>
        {folio.deposit_held_cents > 0 && (
          <div className="flex justify-between text-xs text-muted-foreground">
            <span>Balance due on arrival</span>
            <span>
              {centsToCurrency(
                folio.balance_due_on_arrival_cents,
                folio.currency,
              )}
            </span>
          </div>
        )}

        {folio.deposit_policy_kind !== "none" && (
          <div className="mt-2 rounded-md bg-muted/40 p-2 text-xs space-y-0.5">
            <p className="font-medium text-muted-foreground">Deposit policy</p>
            <p>
              Kind: <strong>{folio.deposit_policy_kind}</strong>
              {folio.deposit_policy_kind === "pct" && (
                <> · {(folio.deposit_pct_bps / 100).toFixed(0)}%</>
              )}
              {folio.deposit_policy_kind === "fixed" && (
                <> · {centsToCurrency(folio.deposit_fixed_cents, folio.currency)}</>
              )}
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Admin: post charge form ──────────────────────────────────────────────────

function PostChargeForm({
  hotelId,
  rid,
  folio,
}: {
  hotelId: string;
  rid: string;
  folio: FolioOut;
}) {
  const qc = useQueryClient();
  const [lineType, setLineType] = useState<FolioLineType>("room_night");
  const [description, setDescription] = useState("");
  const [quantity, setQuantity] = useState("1");
  const [unitPrice, setUnitPrice] = useState("");

  const mut = useMutation({
    mutationFn: () =>
      addFolioLine(hotelId, rid, {
        line_type: lineType,
        description: description.trim(),
        quantity: parseInt(quantity, 10) || 1,
        unit_price_cents: Math.round(parseFloat(unitPrice) * 100),
      }),
    onSuccess: (data) => {
      toast.success("Charge posted to folio");
      qc.setQueryData(["hotel-folio", hotelId, rid], data);
      setDescription("");
      setUnitPrice("");
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof ApiError ? err.detail : "Failed to post charge",
      ),
  });

  const disabled =
    folio.status !== "open" ||
    mut.isPending ||
    !description.trim() ||
    !unitPrice.trim() ||
    parseFloat(unitPrice) < 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm flex items-center gap-1">
          <Plus className="h-4 w-4" /> Post Charge
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {folio.status !== "open" && (
          <p className="text-xs text-muted-foreground">
            Folio is closed — no new charges can be posted.
          </p>
        )}
        <div className="space-y-1">
          <Label className="text-xs">Type</Label>
          <Select
            value={lineType}
            onValueChange={(v) => setLineType(v as FolioLineType)}
          >
            <SelectTrigger className="h-8 text-xs" data-testid="charge-type-select">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="room_night">Room Night</SelectItem>
              <SelectItem value="addon">Add-on</SelectItem>
              <SelectItem value="tax">Tax</SelectItem>
              <SelectItem value="fee">Fee</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Description</Label>
          <Input
            className="h-8 text-xs"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Room service"
            data-testid="charge-description-input"
          />
        </div>
        <div className="grid grid-cols-2 gap-2">
          <div className="space-y-1">
            <Label className="text-xs">Qty</Label>
            <Input
              className="h-8 text-xs"
              type="number"
              min={1}
              value={quantity}
              onChange={(e) => setQuantity(e.target.value)}
              data-testid="charge-qty-input"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-xs">Unit price ($)</Label>
            <Input
              className="h-8 text-xs"
              type="number"
              min={0}
              step={0.01}
              value={unitPrice}
              onChange={(e) => setUnitPrice(e.target.value)}
              placeholder="0.00"
              data-testid="charge-unit-price-input"
            />
          </div>
        </div>
        <Button
          size="sm"
          className="w-full"
          onClick={() => mut.mutate()}
          disabled={disabled}
          data-testid="post-charge-btn"
        >
          {mut.isPending ? (
            <Loader2 className="h-3 w-3 animate-spin mr-1" />
          ) : (
            <Plus className="h-3 w-3 mr-1" />
          )}
          Post charge
        </Button>
      </CardContent>
    </Card>
  );
}

// ─── Admin: add catalog add-on form ──────────────────────────────────────────

function AddAddonForm({
  hotelId,
  rid,
  folio,
}: {
  hotelId: string;
  rid: string;
  folio: FolioOut;
}) {
  const qc = useQueryClient();
  const [sku, setSku] = useState("");
  const [quantity, setQuantity] = useState("1");

  const mut = useMutation({
    mutationFn: () =>
      addFolioAddon(hotelId, rid, {
        sku: sku.trim(),
        quantity: parseInt(quantity, 10) || 1,
      }),
    onSuccess: (data) => {
      toast.success("Add-on attached to folio");
      qc.setQueryData(["hotel-folio", hotelId, rid], data);
      setSku("");
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof ApiError ? err.detail : "Failed to attach add-on",
      ),
  });

  const disabled =
    folio.status !== "open" ||
    mut.isPending ||
    !sku.trim();

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm flex items-center gap-1">
          <Package className="h-4 w-4" /> Attach Add-on SKU
        </CardTitle>
        <CardDescription className="text-xs">
          Price is resolved server-side from the catalog.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="space-y-1">
          <Label className="text-xs">Catalog SKU</Label>
          <Input
            className="h-8 text-xs"
            value={sku}
            onChange={(e) => setSku(e.target.value)}
            placeholder="sku_breakfast_001"
            data-testid="addon-sku-input"
          />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Qty</Label>
          <Input
            className="h-8 text-xs"
            type="number"
            min={1}
            value={quantity}
            onChange={(e) => setQuantity(e.target.value)}
            data-testid="addon-qty-input"
          />
        </div>
        <Button
          size="sm"
          className="w-full"
          onClick={() => mut.mutate()}
          disabled={disabled}
          data-testid="attach-addon-btn"
        >
          {mut.isPending ? (
            <Loader2 className="h-3 w-3 animate-spin mr-1" />
          ) : (
            <Package className="h-3 w-3 mr-1" />
          )}
          Attach add-on
        </Button>
      </CardContent>
    </Card>
  );
}

// ─── Admin: record payment form ───────────────────────────────────────────────

function RecordPaymentForm({
  hotelId,
  rid,
  folio,
}: {
  hotelId: string;
  rid: string;
  folio: FolioOut;
}) {
  const qc = useQueryClient();
  const [amount, setAmount] = useState("");
  const [method, setMethod] = useState<FolioPaymentMethod>("cash");
  const [reference, setReference] = useState("");

  const mut = useMutation({
    mutationFn: () =>
      recordFolioPayment(hotelId, rid, {
        amount_cents: Math.round(parseFloat(amount) * 100),
        method,
        reference: reference.trim(),
      }),
    onSuccess: (data) => {
      toast.success("Payment recorded");
      qc.setQueryData(["hotel-folio", hotelId, rid], data);
      setAmount("");
      setReference("");
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof ApiError ? err.detail : "Failed to record payment",
      ),
  });

  const disabled =
    folio.status !== "open" ||
    mut.isPending ||
    !amount.trim() ||
    parseFloat(amount) <= 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm flex items-center gap-1">
          <CreditCard className="h-4 w-4" /> Record Payment
        </CardTitle>
        <CardDescription className="text-xs">
          "Wallet" deducts from the guest's platform wallet.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {folio.status !== "open" && (
          <p className="text-xs text-muted-foreground">
            Folio is closed — no payments can be recorded.
          </p>
        )}
        <div className="space-y-1">
          <Label className="text-xs">Amount ($)</Label>
          <Input
            className="h-8 text-xs"
            type="number"
            min={0.01}
            step={0.01}
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            placeholder="0.00"
            data-testid="payment-amount-input"
          />
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Method</Label>
          <Select
            value={method}
            onValueChange={(v) => setMethod(v as FolioPaymentMethod)}
          >
            <SelectTrigger className="h-8 text-xs" data-testid="payment-method-select">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {(Object.keys(PAYMENT_METHOD_LABELS) as FolioPaymentMethod[]).map(
                (m) => (
                  <SelectItem key={m} value={m}>
                    {PAYMENT_METHOD_LABELS[m]}
                  </SelectItem>
                ),
              )}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1">
          <Label className="text-xs">Reference (optional)</Label>
          <Input
            className="h-8 text-xs"
            value={reference}
            onChange={(e) => setReference(e.target.value)}
            placeholder="Card auth #, receipt #"
            data-testid="payment-reference-input"
          />
        </div>
        <Button
          size="sm"
          className="w-full"
          onClick={() => mut.mutate()}
          disabled={disabled}
          data-testid="record-payment-btn"
        >
          {mut.isPending ? (
            <Loader2 className="h-3 w-3 animate-spin mr-1" />
          ) : (
            <CreditCard className="h-3 w-3 mr-1" />
          )}
          Record payment
        </Button>
      </CardContent>
    </Card>
  );
}

// ─── Admin: deposit panel ─────────────────────────────────────────────────────

function DepositPanel({
  hotelId,
  rid,
  folio,
}: {
  hotelId: string;
  rid: string;
  folio: FolioOut;
}) {
  const qc = useQueryClient();
  const [policyKind, setPolicyKind] = useState<DepositPolicyKind>(
    folio.deposit_policy_kind,
  );
  const [pctBps, setPctBps] = useState(String(folio.deposit_pct_bps / 100));
  const [fixedAmount, setFixedAmount] = useState(
    String(folio.deposit_fixed_cents / 100),
  );
  const [depositAmount, setDepositAmount] = useState("");

  const policyMut = useMutation({
    mutationFn: () =>
      setFolioDepositPolicy(hotelId, rid, {
        kind: policyKind,
        pct_bps: Math.round(parseFloat(pctBps || "0") * 100),
        fixed_cents: Math.round(parseFloat(fixedAmount || "0") * 100),
      }),
    onSuccess: (data) => {
      toast.success("Deposit policy updated");
      qc.setQueryData(["hotel-folio", hotelId, rid], data);
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof ApiError ? err.detail : "Failed to update deposit policy",
      ),
  });

  const depositMut = useMutation({
    mutationFn: () =>
      takeFolioDeposit(hotelId, rid, {
        amount_cents: depositAmount
          ? Math.round(parseFloat(depositAmount) * 100)
          : undefined,
      }),
    onSuccess: (data) => {
      toast.success("Deposit held successfully");
      qc.setQueryData(["hotel-folio", hotelId, rid], data);
      setDepositAmount("");
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof ApiError ? err.detail : "Failed to take deposit",
      ),
  });

  const hasDepositAlready = folio.deposit_held_cents > 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm flex items-center gap-1">
          <Lock className="h-4 w-4" /> Deposit Escrow
        </CardTitle>
        {hasDepositAlready && (
          <CardDescription className="text-xs text-green-700 font-medium">
            Deposit already held:{" "}
            {centsToCurrency(folio.deposit_held_cents, folio.currency)}
          </CardDescription>
        )}
      </CardHeader>
      <CardContent className="space-y-3">
        {folio.status !== "open" && (
          <p className="text-xs text-muted-foreground">Folio is closed.</p>
        )}

        <div className="space-y-1">
          <Label className="text-xs">Policy kind</Label>
          <Select
            value={policyKind}
            onValueChange={(v) => setPolicyKind(v as DepositPolicyKind)}
          >
            <SelectTrigger className="h-8 text-xs" data-testid="deposit-policy-select">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="none">None</SelectItem>
              <SelectItem value="pct">Percentage</SelectItem>
              <SelectItem value="fixed">Fixed amount</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {policyKind === "pct" && (
          <div className="space-y-1">
            <Label className="text-xs">Percentage (%)</Label>
            <Input
              className="h-8 text-xs"
              type="number"
              min={0}
              max={100}
              step={0.01}
              value={pctBps}
              onChange={(e) => setPctBps(e.target.value)}
              placeholder="20"
              data-testid="deposit-pct-input"
            />
          </div>
        )}

        {policyKind === "fixed" && (
          <div className="space-y-1">
            <Label className="text-xs">Fixed amount ($)</Label>
            <Input
              className="h-8 text-xs"
              type="number"
              min={0}
              step={0.01}
              value={fixedAmount}
              onChange={(e) => setFixedAmount(e.target.value)}
              placeholder="100.00"
              data-testid="deposit-fixed-input"
            />
          </div>
        )}

        <Button
          size="sm"
          variant="outline"
          className="w-full"
          onClick={() => policyMut.mutate()}
          disabled={folio.status !== "open" || policyMut.isPending}
          data-testid="set-deposit-policy-btn"
        >
          {policyMut.isPending ? (
            <Loader2 className="h-3 w-3 animate-spin mr-1" />
          ) : null}
          Save policy
        </Button>

        <Separator />

        <div className="space-y-1">
          <Label className="text-xs">Hold deposit ($) — leave blank to use policy</Label>
          <Input
            className="h-8 text-xs"
            type="number"
            min={0.01}
            step={0.01}
            value={depositAmount}
            onChange={(e) => setDepositAmount(e.target.value)}
            placeholder="auto from policy"
            data-testid="deposit-amount-input"
          />
        </div>

        <Button
          size="sm"
          className="w-full"
          onClick={() => depositMut.mutate()}
          disabled={
            folio.status !== "open" ||
            hasDepositAlready ||
            depositMut.isPending
          }
          data-testid="take-deposit-btn"
        >
          {depositMut.isPending ? (
            <Loader2 className="h-3 w-3 animate-spin mr-1" />
          ) : (
            <Lock className="h-3 w-3 mr-1" />
          )}
          {hasDepositAlready ? "Deposit already held" : "Hold deposit from wallet"}
        </Button>
      </CardContent>
    </Card>
  );
}

// ─── Admin: close folio ───────────────────────────────────────────────────────

function CloseFolioPanel({
  hotelId,
  rid,
  folio,
}: {
  hotelId: string;
  rid: string;
  folio: FolioOut;
}) {
  const qc = useQueryClient();

  const mut = useMutation({
    mutationFn: () => closeFolio(hotelId, rid),
    onSuccess: (data) => {
      toast.success("Folio closed");
      qc.setQueryData(["hotel-folio", hotelId, rid], data);
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof ApiError ? err.detail : "Failed to close folio",
      ),
  });

  if (folio.status === "closed") {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Folio closed</CardTitle>
          <CardDescription className="text-xs">
            Closed at {fmt(folio.closed_at)}. No further modifications allowed.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  const hasBalance = folio.balance_due_cents > 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm flex items-center gap-1">
          <X className="h-4 w-4" /> Close Folio
        </CardTitle>
        {hasBalance && (
          <CardDescription className="text-xs text-red-600">
            Balance due:{" "}
            {centsToCurrency(folio.balance_due_cents, folio.currency)} — clear
            before closing if required.
          </CardDescription>
        )}
      </CardHeader>
      <CardContent>
        <Button
          size="sm"
          variant="destructive"
          className="w-full"
          onClick={() => mut.mutate()}
          disabled={mut.isPending}
          data-testid="close-folio-btn"
        >
          {mut.isPending ? (
            <Loader2 className="h-3 w-3 animate-spin mr-1" />
          ) : (
            <X className="h-3 w-3 mr-1" />
          )}
          Close folio
        </Button>
      </CardContent>
    </Card>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function FolioDetailPage() {
  const { hotelId = "", rid = "" } = useParams<{
    hotelId: string;
    rid: string;
  }>();
  const token = useAuthStore((s) => s.accessToken);
  const role = getRoleFromAccessToken(token);
  const isAdmin = role === "admin" || role === "root";

  const qc = useQueryClient();

  const query = useQuery<FolioOut>({
    queryKey: ["hotel-folio", hotelId, rid],
    queryFn: () => getFolio(hotelId, rid),
    enabled: !!hotelId && !!rid,
    retry: (failureCount, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 503))
        return false;
      return failureCount < 2;
    },
  });

  const openMut = useMutation({
    mutationFn: () => openFolio(hotelId, rid),
    onSuccess: (data) => {
      toast.success("Folio opened");
      qc.setQueryData(["hotel-folio", hotelId, rid], data);
    },
    onError: (err: unknown) =>
      toast.error(
        err instanceof ApiError ? err.detail : "Failed to open folio",
      ),
  });

  const isNotEnabled =
    query.isError &&
    query.error instanceof ApiError &&
    (query.error.status === 404 || query.error.status === 503);

  if (query.isLoading) {
    return (
      <div className="flex items-center justify-center h-48">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (isNotEnabled) {
    return (
      <div className="p-6 space-y-4">
        <Link
          to="/hotels/folios"
          className="flex items-center gap-1 text-sm text-muted-foreground hover:underline"
        >
          <ChevronLeft className="h-4 w-4" /> Back to folios
        </Link>
        <div className="flex items-center gap-3 rounded-md border border-yellow-200 bg-yellow-50 p-4 text-yellow-800">
          <AlertCircle className="h-5 w-5 shrink-0" />
          <div>
            <p className="font-semibold">Hotel PMS is not enabled</p>
            <p className="text-sm">
              Contact your administrator to enable the HOTEL_PMS_ENABLED feature
              flag.
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="p-6 space-y-4">
        <Link
          to="/hotels/folios"
          className="flex items-center gap-1 text-sm text-muted-foreground hover:underline"
        >
          <ChevronLeft className="h-4 w-4" /> Back to folios
        </Link>
        <div className="flex items-center gap-3 rounded-md border border-red-200 bg-red-50 p-4 text-red-800">
          <AlertCircle className="h-5 w-5 shrink-0" />
          <p>
            {query.error instanceof ApiError
              ? query.error.detail
              : "An error occurred loading the folio."}
          </p>
        </div>
      </div>
    );
  }

  const folio = query.data;

  if (!folio) {
    return (
      <div className="p-6 space-y-4">
        <Link
          to="/hotels/folios"
          className="flex items-center gap-1 text-sm text-muted-foreground hover:underline"
        >
          <ChevronLeft className="h-4 w-4" /> Back to folios
        </Link>
        <p className="text-muted-foreground text-sm">Folio not found.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      {/* Back link */}
      <Link
        to="/hotels/folios"
        className="flex items-center gap-1 text-sm text-muted-foreground hover:underline"
      >
        <ChevronLeft className="h-4 w-4" /> Back to folios
      </Link>

      {/* Header */}
      <PageHeader
        title={`Folio — ${folio.folio_id}`}
        description={`Reservation: ${folio.reservation_id} · Hotel: ${folio.hotel_id}`}
        actions={
          <div className="flex items-center gap-2 flex-wrap">
            <StatusBadge status={folio.status} />
            <Button
              size="sm"
              variant="outline"
              onClick={() => void query.refetch()}
              disabled={query.isFetching}
              data-testid="folio-refresh-btn"
            >
              {query.isFetching ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="h-4 w-4" />
              )}
            </Button>
            {isAdmin && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => openMut.mutate()}
                disabled={openMut.isPending}
                data-testid="open-folio-btn"
              >
                Open folio
              </Button>
            )}
            <a
              href={folioPdfUrl(hotelId, rid)}
              target="_blank"
              rel="noopener noreferrer"
              download
              data-testid="download-pdf-btn"
            >
              <Button size="sm" variant="outline">
                <FileDown className="h-4 w-4 mr-1" />
                Download PDF
              </Button>
            </a>
          </div>
        }
      />

      {/* Meta info */}
      <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
        <span>Guest: {folio.guest_sub || "—"}</span>
        <span>·</span>
        <span>Currency: {folio.currency.toUpperCase()}</span>
        <span>·</span>
        <span>Created: {fmt(folio.created_at)}</span>
        <span>·</span>
        <span>Updated: {fmt(folio.updated_at)}</span>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Left: line items */}
        <div className="lg:col-span-2 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ReceiptText className="h-4 w-4" />
                Charge Lines ({folio.line_items.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              {folio.line_items.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No charge lines yet.
                </p>
              ) : (
                <div>
                  {folio.line_items.map((line) => (
                    <LineItemRow
                      key={line.line_id}
                      line={line}
                      currency={folio.currency}
                    />
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <BalanceSummary folio={folio} />
        </div>

        {/* Right: admin actions */}
        <div className="space-y-4">
          {isAdmin ? (
            <>
              <PostChargeForm hotelId={hotelId} rid={rid} folio={folio} />
              <AddAddonForm hotelId={hotelId} rid={rid} folio={folio} />
              <RecordPaymentForm hotelId={hotelId} rid={rid} folio={folio} />
              <DepositPanel hotelId={hotelId} rid={rid} folio={folio} />
              <CloseFolioPanel hotelId={hotelId} rid={rid} folio={folio} />
            </>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Guest view</CardTitle>
                <CardDescription className="text-xs">
                  Charge management is available to hotel administrators only.
                </CardDescription>
              </CardHeader>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
