import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Building2,
  CreditCard,
  Plus,
  Star,
  Trash2,
  Clock,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { detectCardNetwork, formatCardNumber } from "@/lib/cardNetwork";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import { EmptyState } from "@/components/shared/EmptyState";
import {
  getPaymentMethods,
  addCard,
  createBankSetupIntent,
  verifyMicrodeposits,
  setDefault,
  removePaymentMethod,
} from "@/api/endpoints/billing";
import type { PaymentMethod } from "@/api/types";

// ─── Pending bank verification persistence ────────────────────────

const PENDING_BANK_KEY = "billing-pending-bank";

interface PendingBank {
  setup_intent_id: string;
  account_last4: string;
  routing_last4: string;
}

function loadPendingBank(): PendingBank | null {
  try {
    const raw = localStorage.getItem(PENDING_BANK_KEY);
    return raw ? (JSON.parse(raw) as PendingBank) : null;
  } catch {
    return null;
  }
}

function savePendingBank(data: PendingBank) {
  localStorage.setItem(PENDING_BANK_KEY, JSON.stringify(data));
}

function clearPendingBank() {
  localStorage.removeItem(PENDING_BANK_KEY);
}

// ─── Helpers ──────────────────────────────────────────────────────

const BRAND_COLORS: Record<string, string> = {
  visa: "text-blue-600",
  mastercard: "text-orange-600",
  amex: "text-blue-800",
  discover: "text-orange-500",
  ath: "text-emerald-600",
};

function brandLabel(brand?: string): string {
  if (!brand) return "Card";
  return brand.charAt(0).toUpperCase() + brand.slice(1);
}

/** Parse "$0.32" or "0.32" → 32 cents. Returns null if invalid. */
function parseDollarsToCents(value: string): number | null {
  const n = parseFloat(value.replace(/[^0-9.]/g, ""));
  if (isNaN(n) || n < 0 || n > 0.99) return null;
  return Math.round(n * 100);
}

// ─── Add Bank Account Dialog ──────────────────────────────────────

interface AddBankDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onVerified: () => void;
}

function AddBankDialog({ open, onOpenChange, onVerified }: AddBankDialogProps) {
  const [step, setStep] = useState<"form" | "verify">("form");

  // Step 1 fields
  const [accountHolder, setAccountHolder] = useState("");
  const [routingNumber, setRoutingNumber] = useState("");
  const [accountNumber, setAccountNumber] = useState("");
  const [accountType, setAccountType] = useState<"checking" | "savings">("checking");
  const [formLoading, setFormLoading] = useState(false);

  // Pending state (stored so user can close and return)
  const [pending, setPending] = useState<PendingBank | null>(() => loadPendingBank());

  // Step 2 fields
  const [amount1, setAmount1] = useState("");
  const [amount2, setAmount2] = useState("");
  const [verifyLoading, setVerifyLoading] = useState(false);

  // When dialog opens, check localStorage for an existing pending verification
  const effectivePending = pending ?? loadPendingBank();

  function handleOpen(isOpen: boolean) {
    if (isOpen) {
      const saved = loadPendingBank();
      if (saved) {
        setPending(saved);
        setStep("verify");
      } else {
        setStep("form");
      }
    }
    onOpenChange(isOpen);
  }

  async function handleSubmitBankDetails(e: React.FormEvent) {
    e.preventDefault();
    if (!routingNumber.trim() || !accountNumber.trim() || !accountHolder.trim()) return;
    if (routingNumber.trim().length !== 9) {
      toast.error("Routing number must be 9 digits");
      return;
    }
    setFormLoading(true);
    try {
      const { client_secret } = await createBankSetupIntent();
      // Extract setup_intent_id from client_secret (format: seti_xxx_secret_yyy)
      const setup_intent_id = client_secret.split("_secret_")[0] ?? client_secret;
      const record: PendingBank = {
        setup_intent_id,
        account_last4: accountNumber.slice(-4),
        routing_last4: routingNumber.slice(-4),
      };
      savePendingBank(record);
      setPending(record);
      setStep("verify");
    } catch {
      toast.error("Failed to start bank account setup");
    } finally {
      setFormLoading(false);
    }
  }

  async function handleVerify(e: React.FormEvent) {
    e.preventDefault();
    const active = pending ?? effectivePending;
    if (!active) return;

    const cents1 = parseDollarsToCents(amount1);
    const cents2 = parseDollarsToCents(amount2);

    if (cents1 === null || cents2 === null) {
      toast.error("Enter each deposit as a dollar amount between $0.01 and $0.99");
      return;
    }

    setVerifyLoading(true);
    try {
      await verifyMicrodeposits({
        setup_intent_id: active.setup_intent_id,
        amounts: [cents1, cents2],
      });
      clearPendingBank();
      setPending(null);
      toast.success("Bank account verified and added");
      onOpenChange(false);
      onVerified();
    } catch (err: any) {
      toast.error(err?.message ?? "Verification failed — check the amounts and try again");
    } finally {
      setVerifyLoading(false);
    }
  }

  function handleCancelPending() {
    clearPendingBank();
    setPending(null);
    setStep("form");
    setAmount1("");
    setAmount2("");
  }

  const activePending = pending ?? effectivePending;

  return (
    <Dialog open={open} onOpenChange={handleOpen}>
      <DialogContent>
        {step === "form" && !activePending && (
          <>
            <DialogHeader>
              <DialogTitle>Add Bank Account</DialogTitle>
              <DialogDescription>
                Enter your routing and account numbers. Two small deposits will be sent to
                verify ownership.
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={handleSubmitBankDetails} className="space-y-4 py-2">
              <div className="space-y-1.5">
                <Label htmlFor="bank-holder">Account holder name</Label>
                <Input
                  id="bank-holder"
                  placeholder="Jane Doe"
                  value={accountHolder}
                  onChange={(e) => setAccountHolder(e.target.value)}
                  required
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="bank-routing">Routing number</Label>
                <Input
                  id="bank-routing"
                  placeholder="110000000"
                  maxLength={9}
                  inputMode="numeric"
                  pattern="[0-9]{9}"
                  value={routingNumber}
                  onChange={(e) => setRoutingNumber(e.target.value.replace(/\D/g, ""))}
                  required
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="bank-account">Account number</Label>
                <Input
                  id="bank-account"
                  placeholder="000123456789"
                  inputMode="numeric"
                  value={accountNumber}
                  onChange={(e) => setAccountNumber(e.target.value.replace(/\D/g, ""))}
                  required
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="bank-type">Account type</Label>
                <Select
                  value={accountType}
                  onValueChange={(v) => setAccountType(v as "checking" | "savings")}
                >
                  <SelectTrigger id="bank-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="checking">Checking</SelectItem>
                    <SelectItem value="savings">Savings</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <p className="text-xs text-muted-foreground">
                Two small deposits (each under $1) will appear in your account within 1–2
                business days. You'll confirm those amounts to complete verification.
              </p>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={formLoading}>
                  {formLoading ? "Sending…" : "Submit bank account"}
                </Button>
              </DialogFooter>
            </form>
          </>
        )}

        {(step === "verify" || activePending) && (
          <>
            <DialogHeader>
              <DialogTitle>Verify bank account</DialogTitle>
              <DialogDescription>
                Two small deposits were sent to the account ending in{" "}
                <strong>****{activePending?.account_last4 ?? "????"}
                </strong>. Enter the exact amounts to complete verification.
              </DialogDescription>
            </DialogHeader>
            <form onSubmit={handleVerify} className="space-y-4 py-2">
              <div className="rounded-lg border border-muted bg-muted/20 px-4 py-3 text-sm text-muted-foreground">
                <p className="font-medium text-foreground">Check your bank statement</p>
                <p className="mt-1">
                  Look for two deposits from <span className="font-mono">AMTS</span> or
                  similar, each less than $1.00. Enter both amounts below (e.g. 0.32).
                </p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label htmlFor="deposit-1">First deposit ($)</Label>
                  <Input
                    id="deposit-1"
                    placeholder="0.32"
                    inputMode="decimal"
                    value={amount1}
                    onChange={(e) => setAmount1(e.target.value)}
                    required
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="deposit-2">Second deposit ($)</Label>
                  <Input
                    id="deposit-2"
                    placeholder="0.45"
                    inputMode="decimal"
                    value={amount2}
                    onChange={(e) => setAmount2(e.target.value)}
                    required
                  />
                </div>
              </div>
              <DialogFooter className="flex-col gap-2 sm:flex-row">
                <Button
                  type="button"
                  variant="ghost"
                  className="text-destructive hover:text-destructive"
                  onClick={handleCancelPending}
                >
                  Cancel &amp; start over
                </Button>
                <Button type="submit" disabled={verifyLoading || !amount1 || !amount2}>
                  {verifyLoading ? "Verifying…" : "Confirm deposits"}
                </Button>
              </DialogFooter>
            </form>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

// ─── Main component ───────────────────────────────────────────────

/** Parse "MM / YY" or "MM/YY" → { exp_month, exp_year }. Returns null if invalid. */
function parseExpiry(raw: string): { exp_month: number; exp_year: number } | null {
  const parts = raw.replace(/\s/g, "").split("/");
  if (parts.length !== 2) return null;
  const month = parseInt(parts[0]!, 10);
  let year = parseInt(parts[1]!, 10);
  if (isNaN(month) || isNaN(year)) return null;
  if (month < 1 || month > 12) return null;
  if (year < 100) year += 2000;
  return { exp_month: month, exp_year: year };
}

export function PaymentMethods() {
  const queryClient = useQueryClient();
  const [addCardOpen, setAddCardOpen] = useState(false);
  const [addBankOpen, setAddBankOpen] = useState(false);
  const [deleting, setDeleting] = useState<PaymentMethod | null>(null);

  // Add card form state
  const [cardName, setCardName] = useState("");
  const [cardNumber, setCardNumber] = useState("");
  const [cardExpiry, setCardExpiry] = useState("");
  const [cardCvc, setCardCvc] = useState("");

  const hasPendingBank = Boolean(loadPendingBank());

  const methodsQuery = useQuery({
    queryKey: ["billing", "payment-methods"],
    queryFn: getPaymentMethods,
  });

  const addCardMutation = useMutation({
    mutationFn: (body: { card_number: string; exp_month: number; exp_year: number; cvc: string; cardholder_name?: string }) =>
      addCard(body),
    onSuccess: () => {
      toast.success("Card added successfully");
      setAddCardOpen(false);
      setCardName("");
      setCardNumber("");
      setCardExpiry("");
      setCardCvc("");
      queryClient.invalidateQueries({ queryKey: ["billing", "payment-methods"] });
    },
    onError: (err: any) => {
      toast.error(err?.message ?? "Failed to add card");
    },
  });

  const defaultMutation = useMutation({
    mutationFn: (id: string) => setDefault({ payment_method_id: id }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["billing", "payment-methods"] });
      toast.success("Default payment method updated");
    },
    onError: () => {
      toast.error("Failed to set default method");
    },
  });

  const removeMutation = useMutation({
    mutationFn: (id: string) => removePaymentMethod(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["billing", "payment-methods"] });
      setDeleting(null);
      toast.success("Payment method removed");
    },
    onError: () => {
      toast.error("Failed to remove payment method");
    },
  });

  const methods: PaymentMethod[] = Array.isArray(methodsQuery.data) ? methodsQuery.data : [];

  if (methodsQuery.isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-20 w-full rounded-xl" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {methods.length} payment method{methods.length !== 1 ? "s" : ""} saved
        </p>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => setAddBankOpen(true)}>
            <Building2 className="mr-1 h-3.5 w-3.5" />
            Add Bank Account
            {hasPendingBank && (
              <Clock className="ml-1 h-3 w-3 text-orange-500" />
            )}
          </Button>
          <Button variant="outline" size="sm" onClick={() => setAddCardOpen(true)}>
            <Plus className="mr-1 h-3.5 w-3.5" />
            Add Card
          </Button>
        </div>
      </div>

      {/* Pending bank verification banner */}
      {hasPendingBank && (
        <button
          type="button"
          className="w-full rounded-lg border border-orange-200 bg-orange-50 px-4 py-3 text-left text-sm dark:border-orange-900 dark:bg-orange-950/30"
          onClick={() => setAddBankOpen(true)}
        >
          <p className="font-medium text-orange-800 dark:text-orange-300">
            Bank account pending verification
          </p>
          <p className="mt-0.5 text-xs text-orange-700 dark:text-orange-400">
            Check your bank statement for two small deposits and click here to confirm the
            amounts.
          </p>
        </button>
      )}

      {methods.length === 0 && !hasPendingBank ? (
        <EmptyState
          icon={<CreditCard className="h-8 w-8" />}
          title="No payment methods"
          description="Add a payment method to get started"
          className="py-16"
        />
      ) : (
        <div className="space-y-3">
          {methods.map((method) => (
            <Card key={method.payment_method_id}>
              <CardContent className="flex items-center gap-4 p-4">
                <div
                  className={`shrink-0 ${
                    method.method_type === "us_bank_account"
                      ? "text-muted-foreground"
                      : (BRAND_COLORS[method.brand ?? ""] ?? "text-muted-foreground")
                  }`}
                >
                  {method.method_type === "us_bank_account" ? (
                    <Building2 className="h-8 w-8" />
                  ) : (
                    <CreditCard className="h-8 w-8" />
                  )}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold">
                      {method.method_type === "us_bank_account"
                        ? (method.label ?? "Bank account")
                        : brandLabel(method.brand)}
                    </span>
                    <span className="text-sm text-muted-foreground">
                      •••• {method.last4 ?? "????"}
                    </span>
                    {method.is_default && (
                      <Badge variant="secondary" className="text-[10px]">
                        Default
                      </Badge>
                    )}
                  </div>
                  <div className="mt-0.5 flex items-center gap-3 text-xs text-muted-foreground">
                    {method.exp_month != null && method.exp_year != null && (
                      <span>
                        Expires {String(method.exp_month).padStart(2, "0")}/{method.exp_year}
                      </span>
                    )}
                    {method.label && method.method_type !== "us_bank_account" && (
                      <span>{method.label}</span>
                    )}
                    {method.method_type && (
                      <span className="capitalize">
                        {method.method_type === "us_bank_account" ? "Bank account" : method.method_type}
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex shrink-0 gap-1">
                  {!method.is_default && (
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8"
                      title="Set as default"
                      onClick={() => defaultMutation.mutate(method.payment_method_id)}
                      disabled={defaultMutation.isPending}
                    >
                      <Star className="h-3.5 w-3.5" />
                    </Button>
                  )}
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 text-destructive"
                    title="Remove"
                    onClick={() => setDeleting(method)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Add card dialog */}
      <Dialog open={addCardOpen} onOpenChange={(o) => { if (!addCardMutation.isPending) setAddCardOpen(o); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Card</DialogTitle>
            <DialogDescription>
              Enter your card details to add a new payment method.
            </DialogDescription>
          </DialogHeader>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              const expiry = parseExpiry(cardExpiry);
              if (!expiry) {
                toast.error("Invalid expiry — use MM / YY format");
                return;
              }
              const number = cardNumber.replace(/\s/g, "").replace(/-/g, "");
              if (number.length < 13 || number.length > 19) {
                toast.error("Invalid card number");
                return;
              }
              addCardMutation.mutate({
                card_number: number,
                exp_month: expiry.exp_month,
                exp_year: expiry.exp_year,
                cvc: cardCvc.trim(),
                cardholder_name: cardName.trim() || undefined,
              });
            }}
            className="space-y-4 py-2"
          >
            <div className="space-y-1.5">
              <Label htmlFor="card-name">Name on card</Label>
              <Input
                id="card-name"
                placeholder="Jane Doe"
                autoComplete="cc-name"
                value={cardName}
                onChange={(e) => setCardName(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="card-number">Card Number</Label>
              <div className="relative">
                <Input
                  id="card-number"
                  placeholder="4242 4242 4242 4242"
                  autoComplete="cc-number"
                  inputMode="numeric"
                  value={cardNumber}
                  onChange={(e) => setCardNumber(formatCardNumber(e.target.value))}
                  className="pr-20"
                  required
                />
                {(() => {
                  const net = detectCardNetwork(cardNumber);
                  if (!cardNumber.trim()) return null;
                  return (
                    <span
                      data-testid="card-network-badge"
                      className={`pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs font-semibold ${
                        BRAND_COLORS[net.id] ?? "text-muted-foreground"
                      }`}
                    >
                      {net.label}
                    </span>
                  );
                })()}
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label htmlFor="card-expiry">Expiry</Label>
                <Input
                  id="card-expiry"
                  placeholder="MM / YY"
                  value={cardExpiry}
                  onChange={(e) => setCardExpiry(e.target.value)}
                  required
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="card-cvc">CVC</Label>
                <Input
                  id="card-cvc"
                  placeholder="123"
                  inputMode="numeric"
                  value={cardCvc}
                  onChange={(e) => setCardCvc(e.target.value)}
                  required
                />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              In production, this form would use Stripe Elements for PCI-compliant card collection.
            </p>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setAddCardOpen(false)} disabled={addCardMutation.isPending}>
                Cancel
              </Button>
              <Button type="submit" disabled={addCardMutation.isPending}>
                {addCardMutation.isPending ? "Adding…" : "Add Card"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Add bank account dialog */}
      <AddBankDialog
        open={addBankOpen}
        onOpenChange={setAddBankOpen}
        onVerified={() => queryClient.invalidateQueries({ queryKey: ["billing", "payment-methods"] })}
      />

      {/* Delete confirmation */}
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(open) => { if (!open) setDeleting(null); }}
        title="Remove Payment Method"
        description={`Remove ${
          deleting?.method_type === "us_bank_account"
            ? (deleting.label ?? "bank account")
            : brandLabel(deleting?.brand)
        } ending in ${deleting?.last4 ?? "????"}?`}
        confirmLabel="Remove"
        variant="danger"
        onConfirm={() => {
          if (deleting) removeMutation.mutate(deleting.payment_method_id);
        }}
        loading={removeMutation.isPending}
      />
    </div>
  );
}
