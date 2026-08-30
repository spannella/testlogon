import { useState, useMemo, useEffect } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  CheckCircle2,
  XCircle,
  CreditCard,
  Star,
  Tag,
  Loader2,
  X,
  Bitcoin,
  RefreshCw,
  AlertTriangle,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import {
  getCartItems,
  getCartTotal,
  purchaseCart,
} from "@/api/endpoints/cart";
import { validatePromoCode } from "@/api/endpoints/promoCodes";
import { getPaymentMethods } from "@/api/endpoints/billing";
import { quoteFee, type FeeQuote } from "@/api/endpoints/fees";
import { getBalance, mergeBalances } from "@/api/endpoints/custody";
import {
  quoteExpirySeconds,
  insufficientForCents,
  rateLine,
  totalLine,
  feeLine,
  formatCoin,
  formatCountdown,
} from "@/lib/checkoutCrypto";
import type { PaymentMethod, PromoValidateOut } from "@/api/types";
import { ApiError } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";

function formatCents(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
  }).format(cents / 100);
}

export default function Checkout() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const cartId = searchParams.get("cartId") ?? "";

  const [selectedMethodId, setSelectedMethodId] = useState<string | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [purchaseResult, setPurchaseResult] = useState<
    "idle" | "success" | "error"
  >("idle");
  const [orderId, setOrderId] = useState("");

  // Pay-with-crypto-balance state (FE-152)
  const [payCrypto, setPayCrypto] = useState(false);
  const [cryptoAsset, setCryptoAsset] = useState<string | null>(null);
  const [quote, setQuote] = useState<FeeQuote | null>(null);
  const [quoteLoading, setQuoteLoading] = useState(false);
  const [quoteError, setQuoteError] = useState("");
  const [cryptoUnavailable, setCryptoUnavailable] = useState(false);
  const [nowSec, setNowSec] = useState(() => Math.floor(Date.now() / 1000));

  // Promo code state (SHOP-002)
  const [promoCode, setPromoCode] = useState("");
  const [promoResult, setPromoResult] = useState<PromoValidateOut | null>(null);
  const [promoError, setPromoError] = useState("");
  const [promoLoading, setPromoLoading] = useState(false);
  const [promoExpanded, setPromoExpanded] = useState(false);

  const itemsQuery = useQuery({
    queryKey: ["cart-items", cartId],
    queryFn: () => getCartItems(cartId),
    enabled: !!cartId,
  });

  const totalQuery = useQuery({
    queryKey: ["cart-total", cartId],
    queryFn: () => getCartTotal(cartId),
    enabled: !!cartId,
  });

  const methodsQuery = useQuery({
    queryKey: ["billing", "payment-methods"],
    queryFn: getPaymentMethods,
  });

  // Crypto balances (custody). Degrade on 404 -> hide the crypto option.
  const balanceQuery = useQuery({
    queryKey: ["custody", "balance"],
    queryFn: getBalance,
    retry: false,
  });

  const items = itemsQuery.data?.items ?? [];
  const total = totalQuery.data;
  const methods: PaymentMethod[] = Array.isArray(methodsQuery.data) ? methodsQuery.data : [];

  const cryptoAvailable = balanceQuery.isSuccess && !!balanceQuery.data;
  const balanceRows = useMemo(
    () => mergeBalances(balanceQuery.data?.balances),
    [balanceQuery.data],
  );
  const selectedRow = useMemo(
    () => balanceRows.find((r) => r.symbol === cryptoAsset) ?? null,
    [balanceRows, cryptoAsset],
  );
  const selectedBalance = selectedRow ? Number(selectedRow.balance) : 0;
  const secondsLeft = quote ? quoteExpirySeconds(quote.expires_at, nowSec) : 0;
  const quoteStale = !!quote && secondsLeft <= 0;
  const insufficient =
    !!quote && !quoteStale && insufficientForCents(selectedBalance, quote);

  // Derive creator_user_id from cart items for promo validation
  // Falls back to the current user's ID when items lack creator info
  const currentUserId = useAuthStore((s) => s.userId);
  const creatorId = useMemo(() => {
    const ids = new Set(
      items
        .map((i) => (i as any).creator_user_id ?? (i as any).seller_id)
        .filter(Boolean),
    );
    if (ids.size === 1) return [...ids][0] as string;
    // Fallback: use current user as creator (self-created items)
    return currentUserId ?? undefined;
  }, [items, currentUserId]);

  // Effective total considering promo discount
  const effectiveTotal = promoResult
    ? promoResult.final_price_cents
    : total?.total_cents ?? 0;

  // --- Pay-with-crypto quote lifecycle (FE-152) ------------------------------
  // Fetch a fresh 60s rate-locked quote for the given asset at the current
  // effective order total. Degrade on 404 -> crypto pay unavailable.
  const fetchQuote = async (asset: string, amountCents: number) => {
    if (!asset || amountCents <= 0) return;
    setQuoteLoading(true);
    setQuoteError("");
    try {
      const q = await quoteFee({ amount_cents: amountCents, pay_with: asset });
      setQuote(q);
      setNowSec(Math.floor(Date.now() / 1000));
    } catch (err) {
      const status = err instanceof ApiError ? err.status : 0;
      if (status === 404) {
        setCryptoUnavailable(true);
        setPayCrypto(false);
        setQuote(null);
      } else {
        setQuote(null);
        setQuoteError(
          err instanceof ApiError ? err.detail : "Could not get a rate. Try again.",
        );
      }
    } finally {
      setQuoteLoading(false);
    }
  };

  const handleSelectCryptoAsset = (asset: string) => {
    setPayCrypto(true);
    setSelectedMethodId(null);
    setCryptoAsset(asset);
    setQuote(null);
    void fetchQuote(asset, effectiveTotal);
  };

  const handleRequote = () => {
    if (cryptoAsset) void fetchQuote(cryptoAsset, effectiveTotal);
  };

  // Live countdown tick for the rate lock (1Hz) while a crypto quote is shown.
  useEffect(() => {
    if (!payCrypto || !quote) return;
    const id = setInterval(
      () => setNowSec(Math.floor(Date.now() / 1000)),
      1000,
    );
    return () => clearInterval(id);
  }, [payCrypto, quote]);

    // Promo validation handler
  const handleApplyPromo = async () => {
    if (!promoCode.trim()) return;
    setPromoLoading(true);
    setPromoError("");
    try {
      const result = await validatePromoCode({
        code: promoCode.trim(),
        checkout_type: "shop",
        item_price_cents: total?.total_cents ?? 0,
        creator_user_id: creatorId ?? "",
      });
      if (result.valid) {
        setPromoResult(result);
        setPromoError("");
      } else {
        setPromoError(result.message ?? "Invalid code");
        setPromoResult(null);
      }
    } catch {
      setPromoError("Failed to validate code");
      setPromoResult(null);
    } finally {
      setPromoLoading(false);
    }
  };

  const handleRemovePromo = () => {
    setPromoResult(null);
    setPromoCode("");
    setPromoError("");
  };

  const purchaseMutation = useMutation({
    mutationFn: () => {
      const body: {
        promo_code?: string;
        pay_with?: string;
        quote_token?: string;
      } = {};
      if (promoResult) body.promo_code = promoCode;
      if (payCrypto && quote) {
        body.pay_with = quote.pay_with;
        body.quote_token = quote.quote_token;
      }
      return purchaseCart(cartId, Object.keys(body).length ? body : undefined);
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["carts"] });
      queryClient.invalidateQueries({ queryKey: ["cart-items", cartId] });
      setPurchaseResult("success");
      setOrderId(data.order_id);
      setConfirmOpen(false);
      toast.success("Order placed successfully!");
    },
    onError: (err: unknown) => {
      const detail =
        err instanceof ApiError ? err.detail : undefined;
      const status =
        err instanceof ApiError ? err.status : 0;
      if (status === 409 && payCrypto) {
        // Locked rate lapsed server-side -> re-quote and let the user re-confirm.
        toast.error("Rate expired — refreshing the quote.");
        handleRequote();
      } else if (status === 402 && payCrypto) {
        toast.error(detail || "Insufficient crypto balance.");
        setQuoteError(detail || "Insufficient crypto balance.");
      } else if (status === 422 && detail) {
        // Promo code became invalid between validate and purchase
        setPromoError(detail);
        setPromoResult(null);
        toast.error(detail);
      } else {
        setPurchaseResult("error");
        toast.error("Purchase failed");
      }
      setConfirmOpen(false);
    },
  });

  // Auto-select default payment method
  if (!selectedMethodId && !payCrypto && methods.length > 0) {
    const defaultMethod = methods.find((m) => m.is_default);
    if (defaultMethod) {
      setSelectedMethodId(defaultMethod.payment_method_id);
    } else {
      setSelectedMethodId(methods[0]!.payment_method_id);
    }
  }

  if (!cartId) {
    return (
      <div className="mx-auto max-w-2xl p-4 sm:p-6 text-center">
        <p className="text-muted-foreground">No cart specified.</p>
        <Button variant="outline" className="mt-4" onClick={() => navigate("/cart")}>
          Go to Cart
        </Button>
      </div>
    );
  }

  // Success state
  if (purchaseResult === "success") {
    return (
      <div className="mx-auto max-w-2xl space-y-6 p-4 sm:p-6">
        <Card>
          <CardContent className="flex flex-col items-center gap-4 py-12">
            <CheckCircle2 className="h-16 w-16 text-green-500" />
            <h2 className="text-2xl font-bold">Order Confirmed!</h2>
            <p className="text-muted-foreground">
              Your order <span className="font-mono font-medium">{orderId.slice(0, 12)}...</span> has been placed.
            </p>
            <div className="flex gap-2 pt-4">
              <Button onClick={() => navigate("/shop")}>Continue Shopping</Button>
              <Button variant="outline" onClick={() => navigate("/cart")}>
                Back to Cart
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Error state
  if (purchaseResult === "error") {
    return (
      <div className="mx-auto max-w-2xl space-y-6 p-4 sm:p-6">
        <Card>
          <CardContent className="flex flex-col items-center gap-4 py-12">
            <XCircle className="h-16 w-16 text-destructive" />
            <h2 className="text-2xl font-bold">Purchase Failed</h2>
            <p className="text-muted-foreground">
              Something went wrong processing your order.
            </p>
            <div className="flex gap-2 pt-4">
              <Button onClick={() => setPurchaseResult("idle")}>Try Again</Button>
              <Button variant="outline" onClick={() => navigate("/cart")}>
                Back to Cart
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  const isLoading = itemsQuery.isLoading || totalQuery.isLoading;

  return (
    <div className="mx-auto max-w-2xl space-y-6 p-4 sm:p-6">
      <Button variant="ghost" size="sm" onClick={() => navigate("/cart")}>
        <ArrowLeft className="mr-1 h-4 w-4" />
        Back to Cart
      </Button>

      <h1 className="text-2xl font-bold">Checkout</h1>

      {isLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-40 w-full rounded-xl" />
          <Skeleton className="h-24 w-full rounded-xl" />
        </div>
      ) : (
        <>
          {/* Order summary */}
          <Card>
            <CardHeader>
              <CardTitle>Order Summary</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {items.map((item) => (
                <div key={item.sku} className="flex items-center justify-between text-sm">
                  <div>
                    <span className="font-medium">{item.name}</span>
                    <span className="ml-2 text-muted-foreground">x {item.quantity}</span>
                  </div>
                  <span>{formatCents(item.line_total_cents)}</span>
                </div>
              ))}
              <Separator />
              {promoResult && (
                <div className="flex items-center justify-between text-sm text-green-600" data-testid="promo-discount-line">
                  <span>Promo discount ({promoCode})</span>
                  <span>-{formatCents(promoResult.discount_cents)}</span>
                </div>
              )}
              <div className="flex items-center justify-between font-semibold">
                <span>Total</span>
                <span className="text-lg">
                  {total
                    ? formatCents(effectiveTotal, total.currency)
                    : "..."}
                </span>
              </div>
            </CardContent>
          </Card>

          {/* Promo Code (SHOP-002) */}
          <Card>
            <CardContent className="py-4">
              <button
                className="flex items-center gap-2 text-sm text-primary hover:underline"
                onClick={() => setPromoExpanded(!promoExpanded)}
                data-testid="promo-expand-btn"
              >
                <Tag className="h-4 w-4" />
                Have a promo code?
              </button>
              {promoExpanded && (
                <div className="mt-3 space-y-2">
                  <div className="flex gap-2">
                    <Input
                      placeholder="Enter code"
                      value={promoCode}
                      onChange={(e) => setPromoCode(e.target.value.toUpperCase())}
                      disabled={!!promoResult}
                      onKeyDown={(e) =>
                        e.key === "Enter" && !promoResult && handleApplyPromo()
                      }
                      data-testid="promo-input"
                    />
                    {promoResult ? (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={handleRemovePromo}
                        data-testid="promo-remove-btn"
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    ) : (
                      <Button
                        onClick={handleApplyPromo}
                        disabled={promoLoading || !promoCode.trim()}
                        data-testid="promo-apply-btn"
                      >
                        {promoLoading ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          "Apply"
                        )}
                      </Button>
                    )}
                  </div>
                  {promoError && (
                    <p className="text-sm text-destructive" data-testid="promo-error">
                      {promoError}
                    </p>
                  )}
                  {promoResult && (
                    <p
                      className="text-sm text-green-600 font-medium"
                      data-testid="promo-success"
                    >
                      Code applied: -{formatCents(promoResult.discount_cents)}{" "}
                      discount
                    </p>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Payment method selection */}
          <Card>
            <CardHeader>
              <CardTitle>Payment Method</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {methods.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No payment methods on file.{" "}
                  <button
                    className="text-primary underline"
                    onClick={() => navigate("/billing")}
                  >
                    Add one
                  </button>
                </p>
              ) : (
                methods.map((method) => (
                  <button
                    key={method.payment_method_id}
                    className={`flex w-full items-center gap-3 rounded-lg border px-4 py-3 text-left transition-colors ${
                      selectedMethodId === method.payment_method_id
                        ? "border-primary bg-primary/5"
                        : "hover:bg-accent"
                    }`}
                    onClick={() => {
                      setSelectedMethodId(method.payment_method_id);
                      setPayCrypto(false);
                    }}
                  >
                    <CreditCard className="h-5 w-5 shrink-0 text-muted-foreground" />
                    <div className="min-w-0 flex-1">
                      <span className="text-sm font-medium capitalize">
                        {method.brand ?? "Card"}
                      </span>
                      <span className="ml-2 text-sm text-muted-foreground">
                        •••• {method.last4 ?? "????"}
                      </span>
                    </div>
                    {method.is_default && (
                      <Badge variant="secondary" className="text-[10px]">
                        <Star className="mr-0.5 h-2.5 w-2.5" />
                        Default
                      </Badge>
                    )}
                  </button>
                ))
              )}

              {/* Pay with crypto balance (FE-152) */}
              {cryptoAvailable && !cryptoUnavailable && (
                <>
                  <button
                    className={`flex w-full items-center gap-3 rounded-lg border px-4 py-3 text-left transition-colors ${
                      payCrypto
                        ? "border-primary bg-primary/5"
                        : "hover:bg-accent"
                    }`}
                    onClick={() => {
                      setSelectedMethodId(null);
                      setPayCrypto(true);
                    }}
                    data-testid="pay-crypto-option"
                  >
                    <Bitcoin className="h-5 w-5 shrink-0 text-muted-foreground" />
                    <div className="min-w-0 flex-1">
                      <span className="text-sm font-medium">
                        Pay with crypto balance
                      </span>
                      <span className="ml-2 text-sm text-muted-foreground">
                        any supported coin
                      </span>
                    </div>
                  </button>

                  {payCrypto && (
                    <div className="space-y-3 rounded-lg border border-dashed p-3">
                      {/* Asset picker */}
                      <div>
                        <p className="mb-1.5 text-xs font-medium text-muted-foreground">
                          Choose a coin
                        </p>
                        <div className="flex flex-wrap gap-2">
                          {balanceRows.map((row) => (
                            <button
                              key={row.symbol}
                              className={`rounded-md border px-3 py-1.5 text-sm transition-colors ${
                                cryptoAsset === row.symbol
                                  ? "border-primary bg-primary/10 font-medium"
                                  : "hover:bg-accent"
                              }`}
                              onClick={() => handleSelectCryptoAsset(row.symbol)}
                              data-testid={`crypto-asset-${row.symbol}`}
                            >
                              {row.symbol}
                              <span className="ml-1.5 text-xs text-muted-foreground">
                                {formatCoin(Number(row.balance))}
                              </span>
                            </button>
                          ))}
                        </div>
                      </div>

                      {/* Rate-lock display */}
                      {quoteLoading && (
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                          <Loader2 className="h-4 w-4 animate-spin" />
                          Fetching rate…
                        </div>
                      )}

                      {quoteError && !quoteLoading && (
                        <p className="text-sm text-destructive" data-testid="crypto-quote-error">
                          {quoteError}
                        </p>
                      )}

                      {quote && !quoteLoading && (
                        <div className="space-y-1.5 rounded-md bg-muted/50 p-3 text-sm" data-testid="crypto-rate-lock">
                          <div className="flex items-center justify-between">
                            <span className="text-muted-foreground">{rateLine(quote)}</span>
                            {quoteStale ? (
                              <Badge variant="destructive" className="text-[10px]">
                                Rate expired
                              </Badge>
                            ) : (
                              <Badge variant="secondary" className="text-[10px]" data-testid="crypto-countdown">
                                Locked {formatCountdown(secondsLeft)}
                              </Badge>
                            )}
                          </div>
                          <div className="flex items-center justify-between font-medium">
                            <span>{totalLine(quote)}</span>
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {feeLine(quote)} · balance {formatCoin(selectedBalance)}{" "}
                            {quote.pay_with}
                          </div>

                          {insufficient && (
                            <p className="flex items-center gap-1.5 text-xs text-destructive" data-testid="crypto-insufficient">
                              <AlertTriangle className="h-3.5 w-3.5" />
                              Insufficient {quote.pay_with} balance for this order.
                            </p>
                          )}

                          {(quoteStale || !insufficient) && (
                            <button
                              className="mt-1 flex items-center gap-1 text-xs text-primary hover:underline"
                              onClick={handleRequote}
                              data-testid="crypto-requote"
                            >
                              <RefreshCw className="h-3 w-3" />
                              {quoteStale ? "Refresh rate" : "Re-quote"}
                            </button>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </>
              )}

              {cryptoUnavailable && (
                <p className="text-xs text-muted-foreground" data-testid="crypto-unavailable">
                  Crypto pay unavailable.
                </p>
              )}
            </CardContent>
          </Card>

          {/* Place order */}
          <Button
            size="lg"
            className="w-full"
            disabled={
              items.length === 0 ||
              (payCrypto
                ? !quote || quoteStale || insufficient || quoteLoading
                : !selectedMethodId)
            }
            onClick={() => setConfirmOpen(true)}
            data-testid="place-order-btn"
          >
            {payCrypto && quote && !quoteStale
              ? `Pay ${formatCoin(quote.total_native)} ${quote.pay_with}`
              : "Place Order"}
            {!payCrypto && total
              ? ` — ${formatCents(effectiveTotal, total.currency)}`
              : ""}
          </Button>

          <ConfirmDialog
            open={confirmOpen}
            onOpenChange={setConfirmOpen}
            title="Confirm Purchase"
            description={
              payCrypto && quote
                ? `${totalLine(quote)} (${rateLine(quote)}) for your ${total ? formatCents(effectiveTotal, total.currency) : "..."} order?`
                : `Place your order for ${total ? formatCents(effectiveTotal, total.currency) : "..."}?`
            }
            confirmLabel="Place Order"
            onConfirm={() => purchaseMutation.mutate()}
            loading={purchaseMutation.isPending}
          />
        </>
      )}
    </div>
  );
}
