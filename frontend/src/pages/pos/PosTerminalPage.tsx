import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Store,
  Plus,
  Minus,
  Trash2,
  Banknote,
  CreditCard,
  Wallet,
  Receipt,
  Lock,
  Unlock,
  ShoppingCart,
  RotateCcw,
  BarChart3,
} from "lucide-react";
import { Link } from "react-router-dom";

import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Badge } from "@/components/ui/badge";
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
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

import {
  createRegister,
  openSession,
  closeSession,
  bindTxn,
  getTxn,
  addLineItem,
  listTxnLines,
  setLineQty,
  removeLineItem,
  tenderCash,
  tenderCard,
  tenderWallet,
  getReceiptLink,
  receiptPdfUrl,
  fmtCents,
  type RegisterConfig,
  type RegisterSessionOut,
  type PosTxnDraftOut,
  type PosTransactionOut,
  type PosLineItem,
} from "@/api/endpoints/pos";
import { withApiBase } from "@/api/client";

// Stable idempotency key generator (tender + session open are idempotent).
function idemKey(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

export default function PosTerminalPage() {
  const qc = useQueryClient();

  // ── workflow state ──────────────────────────────────────────────────────────
  const [register, setRegister] = useState<RegisterConfig | null>(null);
  const [session, setSession] = useState<RegisterSessionOut | null>(null);
  const [draft, setDraft] = useState<PosTxnDraftOut | null>(null);
  const [settled, setSettled] = useState<PosTransactionOut | null>(null);

  // register form
  const [regLabel, setRegLabel] = useState("Front Counter");
  const [regLocation, setRegLocation] = useState("store-main");
  const [regCurrency, setRegCurrency] = useState("USD");

  // open-session form
  const [openingFloat, setOpeningFloat] = useState("10000");

  // add-item form (raw SKU)
  const [itemSku, setItemSku] = useState("");
  const [itemName, setItemName] = useState("");
  const [itemPrice, setItemPrice] = useState("");
  const [itemQty, setItemQty] = useState("1");

  // tender state
  const [cashTendered, setCashTendered] = useState("");
  const [cardLast4, setCardLast4] = useState("4242");
  const [cardKind, setCardKind] = useState("visa");
  const [cardPmId, setCardPmId] = useState("pm_card_demo");

  // close-session form
  const [closeOpen, setCloseOpen] = useState(false);
  const [countedCash, setCountedCash] = useState("");

  const currency = register?.default_currency || "USD";

  // ── queries ───────────────────────────────────────────────────────────────
  const linesQuery = useQuery({
    queryKey: ["pos", "lines", draft?.txn_id],
    queryFn: () => listTxnLines(draft!.txn_id),
    enabled: !!draft && draft.status === "draft",
    refetchOnWindowFocus: false,
  });
  const lines: PosLineItem[] = linesQuery.data ?? [];

  const txnTotalQuery = useQuery({
    queryKey: ["pos", "txn", draft?.txn_id],
    queryFn: () => getTxn(draft!.txn_id),
    enabled: !!draft && draft.status === "draft",
    refetchOnWindowFocus: false,
  });
  const liveTotal = txnTotalQuery.data?.total_cents ?? draft?.total_cents ?? 0;

  const computedSubtotal = useMemo(
    () => lines.reduce((s, l) => s + (l.line_total_cents || 0), 0),
    [lines],
  );

  const refreshDraft = () => {
    qc.invalidateQueries({ queryKey: ["pos", "lines", draft?.txn_id] });
    qc.invalidateQueries({ queryKey: ["pos", "txn", draft?.txn_id] });
  };

  // ── mutations ───────────────────────────────────────────────────────────────
  const createRegMut = useMutation({
    mutationFn: () =>
      createRegister({
        label: regLabel.trim(),
        location_id: regLocation.trim(),
        default_currency: regCurrency.trim().toUpperCase(),
      }),
    onSuccess: (reg) => {
      setRegister(reg);
      toast.success("Register created");
    },
    onError: (e: any) =>
      toast.error(
        e?.status === 404
          ? "POS feature is disabled (enable POS_ENABLED on the backend)."
          : e?.message || "Failed to create register",
      ),
  });

  const openSessionMut = useMutation({
    mutationFn: () =>
      openSession({
        register_id: register!.register_id!,
        opening_float_cents: Number(openingFloat) || 0,
        idempotency_key: idemKey("open"),
      }),
    onSuccess: (s) => {
      setSession(s);
      setDraft(null);
      setSettled(null);
      toast.success("Session opened");
    },
    onError: (e: any) => toast.error(e?.message || "Failed to open session"),
  });

  const bindTxnMut = useMutation({
    mutationFn: () =>
      bindTxn(session!.session_id, { correlation_id: idemKey("cart") }),
    onSuccess: (d) => {
      setDraft(d);
      setSettled(null);
      toast.success("New transaction started");
    },
    onError: (e: any) => toast.error(e?.message || "Failed to start transaction"),
  });

  const addItemMut = useMutation({
    mutationFn: () =>
      addLineItem(draft!.txn_id, {
        sku: itemSku.trim(),
        name: itemName.trim(),
        unit_price_cents: Math.round(Number(itemPrice) * 100),
        quantity: Math.max(1, Number(itemQty) || 1),
      }),
    onSuccess: () => {
      setItemSku("");
      setItemName("");
      setItemPrice("");
      setItemQty("1");
      refreshDraft();
      toast.success("Item added");
    },
    onError: (e: any) => toast.error(e?.message || "Failed to add item"),
  });

  const setQtyMut = useMutation({
    mutationFn: ({ sku, quantity }: { sku: string; quantity: number }) =>
      setLineQty(draft!.txn_id, sku, { quantity }),
    onSuccess: () => refreshDraft(),
    onError: (e: any) => toast.error(e?.message || "Failed to update quantity"),
  });

  const removeMut = useMutation({
    mutationFn: (sku: string) => removeLineItem(draft!.txn_id, sku, 9999),
    onSuccess: () => {
      refreshDraft();
      toast.success("Item removed");
    },
    onError: (e: any) => toast.error(e?.message || "Failed to remove item"),
  });

  const cashMut = useMutation({
    mutationFn: () =>
      tenderCash(session!.session_id, draft!.txn_id, {
        amount_tendered_cents: Math.round(Number(cashTendered) * 100),
        idempotency_key: idemKey("cash"),
      }),
    onSuccess: (txn) => {
      setSettled(txn);
      setDraft((d) => (d ? { ...d, status: txn.status } : d));
      toast.success("Cash tender complete");
    },
    onError: (e: any) => toast.error(e?.message || "Cash tender failed"),
  });

  const cardMut = useMutation({
    mutationFn: () =>
      tenderCard(session!.session_id, draft!.txn_id, {
        amount_tendered_cents: liveTotal,
        payment_method_id: cardPmId.trim(),
        idempotency_key: idemKey("card"),
        card_kind: cardKind.trim() || undefined,
        last4: cardLast4.trim() || undefined,
      }),
    onSuccess: (txn) => {
      setSettled(txn);
      setDraft((d) => (d ? { ...d, status: txn.status } : d));
      toast.success("Card tender complete");
    },
    onError: (e: any) => toast.error(e?.message || "Card tender failed"),
  });

  const walletMut = useMutation({
    mutationFn: () =>
      tenderWallet(session!.session_id, draft!.txn_id, {
        amount_tendered_cents: liveTotal,
        idempotency_key: idemKey("wallet"),
      }),
    onSuccess: (txn) => {
      setSettled(txn);
      setDraft((d) => (d ? { ...d, status: txn.status } : d));
      toast.success("Wallet tender complete");
    },
    onError: (e: any) => toast.error(e?.message || "Wallet tender failed"),
  });

  const closeSessionMut = useMutation({
    mutationFn: () =>
      closeSession(session!.session_id, {
        counted_cash_cents: Math.round(Number(countedCash) * 100),
      }),
    onSuccess: (s) => {
      setSession(s);
      setDraft(null);
      setSettled(null);
      setCloseOpen(false);
      const os = s.over_short_cents ?? 0;
      toast.success(
        `Session closed · ${os === 0 ? "balanced" : os > 0 ? `over ${fmtCents(os, currency)}` : `short ${fmtCents(-os, currency)}`}`,
      );
    },
    onError: (e: any) => toast.error(e?.message || "Failed to close session"),
  });

  // ── receipt ─────────────────────────────────────────────────────────────────
  const [receiptOpen, setReceiptOpen] = useState(false);
  const receiptQuery = useQuery({
    queryKey: ["pos", "receipt", settled?.txn_id],
    queryFn: () => getReceiptLink(settled!.txn_id),
    enabled: receiptOpen && !!settled,
  });

  const change = settled?.tenders?.find((t) => t.kind === "cash")?.change_due_cents ?? 0;
  const cashTenderedNum = Math.round(Number(cashTendered) * 100);
  const sessionOpen = session?.status === "open";

  // ── render: step 1 — register ─────────────────────────────────────────────────
  if (!register) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="POS Register Terminal"
          description="Open a register, ring up a sale, take payment, and print receipts."
          actions={
            <Button variant="outline" asChild>
              <Link to="/ofbiz/pos/reports">
                <BarChart3 className="mr-2 h-4 w-4" /> Session Reports
              </Link>
            </Button>
          }
        />
        <Card className="max-w-lg">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Store className="h-5 w-5" /> Create / select a register
            </CardTitle>
            <CardDescription>A register is a physical terminal at a store location.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="reg-label">Register label</Label>
              <Input id="reg-label" value={regLabel} onChange={(e) => setRegLabel(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="reg-loc">Location ID</Label>
              <Input id="reg-loc" value={regLocation} onChange={(e) => setRegLocation(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="reg-cur">Currency</Label>
              <Input
                id="reg-cur"
                value={regCurrency}
                maxLength={3}
                onChange={(e) => setRegCurrency(e.target.value)}
              />
            </div>
            <Button
              className="w-full"
              onClick={() => createRegMut.mutate()}
              disabled={createRegMut.isPending || !regLabel.trim() || !regLocation.trim()}
            >
              {createRegMut.isPending ? "Creating…" : "Create register"}
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  // ── render: step 2 — open session ─────────────────────────────────────────────
  if (!sessionOpen) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="POS Register Terminal"
          description={`${register.label} · ${register.location_id}`}
          actions={
            <Button variant="outline" asChild>
              <Link to="/ofbiz/pos/reports">
                <BarChart3 className="mr-2 h-4 w-4" /> Session Reports
              </Link>
            </Button>
          }
        />
        <Card className="max-w-lg">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Unlock className="h-5 w-5" /> Open till
            </CardTitle>
            <CardDescription>
              Count the opening cash float, then open the session to start ringing sales.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="float">Opening float (cents)</Label>
              <Input
                id="float"
                type="number"
                value={openingFloat}
                onChange={(e) => setOpeningFloat(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                = {fmtCents(Number(openingFloat) || 0, currency)}
              </p>
            </div>
            <div className="flex gap-2">
              <Button
                className="flex-1"
                onClick={() => openSessionMut.mutate()}
                disabled={openSessionMut.isPending}
              >
                {openSessionMut.isPending ? "Opening…" : "Open session"}
              </Button>
              <Button variant="outline" onClick={() => setRegister(null)}>
                Change register
              </Button>
            </div>
            {session?.status === "closed" && (
              <p className="text-sm text-muted-foreground">
                Last session closed at {session.closed_at ? new Date(session.closed_at * 1000).toLocaleString() : "—"}.
              </p>
            )}
          </CardContent>
        </Card>
      </div>
    );
  }

  // ── render: step 3 — terminal ─────────────────────────────────────────────────
  return (
    <div className="space-y-6">
      <PageHeader
        title="POS Register Terminal"
        description={`${register.label} · session ${session.session_id.slice(0, 12)}…`}
        actions={
          <div className="flex items-center gap-2">
            <Badge variant="secondary">Float {fmtCents(session.opening_float_cents, currency)}</Badge>
            <Button variant="outline" asChild>
              <Link to="/ofbiz/pos/reports">
                <BarChart3 className="mr-2 h-4 w-4" /> Reports
              </Link>
            </Button>
            <Button variant="destructive" onClick={() => setCloseOpen(true)}>
              <Lock className="mr-2 h-4 w-4" /> Close till
            </Button>
          </div>
        }
      />

      {!draft ? (
        <Card>
          <CardContent className="py-10">
            <EmptyState
              icon={<ShoppingCart className="h-7 w-7" />}
              title="No active transaction"
              description="Start a new sale to begin ringing items."
              action={{ label: "New sale", onClick: () => bindTxnMut.mutate() }}
            />
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-6 lg:grid-cols-3">
          {/* Cart + add item */}
          <div className="space-y-6 lg:col-span-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <ShoppingCart className="h-4 w-4" /> Cart
                  <Badge variant="outline" className="ml-2">
                    {draft.status}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {lines.length === 0 ? (
                  <p className="py-6 text-center text-sm text-muted-foreground">
                    No items yet. Add one below.
                  </p>
                ) : (
                  <div className="divide-y rounded-md border">
                    {lines.map((l) => (
                      <div key={l.sku} className="flex items-center gap-3 p-3">
                        <div className="min-w-0 flex-1">
                          <p className="truncate font-medium">{l.name}</p>
                          <p className="text-xs text-muted-foreground">
                            {l.sku} · {fmtCents(l.unit_price_cents, currency)} ea
                          </p>
                        </div>
                        {draft.status === "draft" && (
                          <div className="flex items-center gap-1">
                            <Button
                              size="icon"
                              variant="outline"
                              className="h-7 w-7"
                              onClick={() =>
                                setQtyMut.mutate({ sku: l.sku, quantity: Math.max(0, l.quantity - 1) })
                              }
                            >
                              <Minus className="h-3 w-3" />
                            </Button>
                            <span className="w-8 text-center text-sm tabular-nums">{l.quantity}</span>
                            <Button
                              size="icon"
                              variant="outline"
                              className="h-7 w-7"
                              onClick={() => setQtyMut.mutate({ sku: l.sku, quantity: l.quantity + 1 })}
                            >
                              <Plus className="h-3 w-3" />
                            </Button>
                          </div>
                        )}
                        <div className="w-20 text-right font-medium tabular-nums">
                          {fmtCents(l.line_total_cents, currency)}
                        </div>
                        {draft.status === "draft" && (
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-7 w-7 text-destructive"
                            onClick={() => removeMut.mutate(l.sku)}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {draft.status === "draft" && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Add item</CardTitle>
                  <CardDescription>Ring a raw SKU with name and price.</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
                    <div className="space-y-1.5">
                      <Label htmlFor="sku">SKU</Label>
                      <Input id="sku" value={itemSku} onChange={(e) => setItemSku(e.target.value)} />
                    </div>
                    <div className="space-y-1.5 col-span-2">
                      <Label htmlFor="iname">Name</Label>
                      <Input id="iname" value={itemName} onChange={(e) => setItemName(e.target.value)} />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="iprice">Price</Label>
                      <Input
                        id="iprice"
                        type="number"
                        step="0.01"
                        value={itemPrice}
                        onChange={(e) => setItemPrice(e.target.value)}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="iqty">Qty</Label>
                      <Input
                        id="iqty"
                        type="number"
                        min={1}
                        value={itemQty}
                        onChange={(e) => setItemQty(e.target.value)}
                      />
                    </div>
                  </div>
                  <Button
                    className="mt-4"
                    onClick={() => addItemMut.mutate()}
                    disabled={
                      addItemMut.isPending ||
                      !itemSku.trim() ||
                      !itemName.trim() ||
                      itemPrice === "" ||
                      Number(itemPrice) < 0
                    }
                  >
                    <Plus className="mr-2 h-4 w-4" /> Add to cart
                  </Button>
                </CardContent>
              </Card>
            )}
          </div>

          {/* Totals + tender / receipt */}
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Total due</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Subtotal</span>
                  <span className="tabular-nums">{fmtCents(computedSubtotal, currency)}</span>
                </div>
                <Separator />
                <div className="flex justify-between text-lg font-semibold">
                  <span>Total</span>
                  <span className="tabular-nums">{fmtCents(liveTotal, currency)}</span>
                </div>
              </CardContent>
            </Card>

            {draft.status === "draft" ? (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Take payment</CardTitle>
                </CardHeader>
                <CardContent>
                  <Tabs defaultValue="cash">
                    <TabsList className="grid w-full grid-cols-3">
                      <TabsTrigger value="cash">
                        <Banknote className="mr-1 h-4 w-4" /> Cash
                      </TabsTrigger>
                      <TabsTrigger value="card">
                        <CreditCard className="mr-1 h-4 w-4" /> Card
                      </TabsTrigger>
                      <TabsTrigger value="wallet">
                        <Wallet className="mr-1 h-4 w-4" /> Wallet
                      </TabsTrigger>
                    </TabsList>

                    <TabsContent value="cash" className="space-y-3 pt-3">
                      <div className="space-y-1.5">
                        <Label htmlFor="cash">Cash tendered</Label>
                        <Input
                          id="cash"
                          type="number"
                          step="0.01"
                          placeholder={(liveTotal / 100).toFixed(2)}
                          value={cashTendered}
                          onChange={(e) => setCashTendered(e.target.value)}
                        />
                      </div>
                      {cashTendered !== "" && cashTenderedNum >= liveTotal && (
                        <p className="text-sm">
                          Change due:{" "}
                          <span className="font-semibold">
                            {fmtCents(cashTenderedNum - liveTotal, currency)}
                          </span>
                        </p>
                      )}
                      <Button
                        className="w-full"
                        onClick={() => cashMut.mutate()}
                        disabled={cashMut.isPending || lines.length === 0 || cashTenderedNum < liveTotal}
                      >
                        {cashMut.isPending ? "Processing…" : "Tender cash"}
                      </Button>
                    </TabsContent>

                    <TabsContent value="card" className="space-y-3 pt-3">
                      <div className="grid grid-cols-2 gap-3">
                        <div className="space-y-1.5">
                          <Label htmlFor="ckind">Card type</Label>
                          <Input id="ckind" value={cardKind} onChange={(e) => setCardKind(e.target.value)} />
                        </div>
                        <div className="space-y-1.5">
                          <Label htmlFor="clast4">Last 4</Label>
                          <Input
                            id="clast4"
                            maxLength={4}
                            value={cardLast4}
                            onChange={(e) => setCardLast4(e.target.value)}
                          />
                        </div>
                      </div>
                      <div className="space-y-1.5">
                        <Label htmlFor="cpm">Payment method ID</Label>
                        <Input id="cpm" value={cardPmId} onChange={(e) => setCardPmId(e.target.value)} />
                      </div>
                      <Button
                        className="w-full"
                        onClick={() => cardMut.mutate()}
                        disabled={cardMut.isPending || lines.length === 0 || liveTotal <= 0 || !cardPmId.trim()}
                      >
                        {cardMut.isPending ? "Processing…" : `Charge ${fmtCents(liveTotal, currency)}`}
                      </Button>
                    </TabsContent>

                    <TabsContent value="wallet" className="space-y-3 pt-3">
                      <p className="text-sm text-muted-foreground">
                        Debit {fmtCents(liveTotal, currency)} from the in-platform wallet.
                      </p>
                      <Button
                        className="w-full"
                        onClick={() => walletMut.mutate()}
                        disabled={walletMut.isPending || lines.length === 0 || liveTotal <= 0}
                      >
                        {walletMut.isPending ? "Processing…" : `Pay ${fmtCents(liveTotal, currency)} from wallet`}
                      </Button>
                    </TabsContent>
                  </Tabs>
                </CardContent>
              </Card>
            ) : (
              <Card className="border-green-500/40">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-base text-green-600">
                    <Receipt className="h-4 w-4" /> Payment complete
                  </CardTitle>
                  <CardDescription className="capitalize">Status: {settled?.status}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="space-y-1 text-sm">
                    {(settled?.tenders ?? []).map((t, i) => (
                      <div key={i} className="flex justify-between">
                        <span className="capitalize text-muted-foreground">{t.kind}</span>
                        <span className="tabular-nums">{fmtCents(t.amount_cents, currency)}</span>
                      </div>
                    ))}
                    {change > 0 && (
                      <div className="flex justify-between font-medium">
                        <span>Change given</span>
                        <span className="tabular-nums">{fmtCents(change, currency)}</span>
                      </div>
                    )}
                  </div>
                  <Separator />
                  <div className="grid grid-cols-2 gap-2">
                    <Button variant="outline" onClick={() => setReceiptOpen(true)}>
                      <Receipt className="mr-2 h-4 w-4" /> Receipt
                    </Button>
                    <Button onClick={() => bindTxnMut.mutate()} disabled={bindTxnMut.isPending}>
                      <RotateCcw className="mr-2 h-4 w-4" /> Next sale
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      )}

      {/* Close-session dialog */}
      <Dialog open={closeOpen} onOpenChange={setCloseOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Close till</DialogTitle>
            <DialogDescription>
              Count the physical cash drawer and enter the total to reconcile over/short.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5">
            <Label htmlFor="counted">Counted cash (cents)</Label>
            <Input
              id="counted"
              type="number"
              value={countedCash}
              onChange={(e) => setCountedCash(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              = {fmtCents(Number(countedCash) || 0, currency)}
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCloseOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => closeSessionMut.mutate()}
              disabled={closeSessionMut.isPending || countedCash === ""}
            >
              {closeSessionMut.isPending ? "Closing…" : "Close & reconcile"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Receipt dialog */}
      <Dialog open={receiptOpen} onOpenChange={setReceiptOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Receipt</DialogTitle>
            <DialogDescription>Transaction {settled?.txn_id}</DialogDescription>
          </DialogHeader>
          {receiptQuery.isLoading ? (
            <p className="text-sm text-muted-foreground">Generating receipt…</p>
          ) : receiptQuery.data ? (
            <div className="space-y-2 text-sm">
              <p className="text-muted-foreground">
                Generated {new Date(receiptQuery.data.generated_at * 1000).toLocaleString()}
              </p>
              <p className="break-all font-mono text-xs">{receiptQuery.data.receipt_path}</p>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">Receipt not available.</p>
          )}
          <DialogFooter>
            {settled && (
              <Button asChild>
                <a href={withApiBase(receiptPdfUrl(settled.txn_id))} target="_blank" rel="noreferrer">
                  <Receipt className="mr-2 h-4 w-4" /> Download PDF
                </a>
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
