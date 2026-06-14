/**
 * CUS-003: Bank Cards management page.
 *
 * Features:
 *  - List the current user's cards
 *  - Activate / freeze / cancel card (status lifecycle)
 *  - View and manage card attributes
 *
 * Gated by OPEN_BANK_PROJECT_ENABLED + customer_entity_enabled.
 * 404/503 = feature not enabled.
 */

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { CreditCard, RefreshCw, Tag, X, ShieldCheck, ShieldOff, XCircle } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { ApiError } from "@/api/client";
import {
  listCards,
  updateCardStatus,
  listCardAttributes,
  setCardAttribute,
  deleteCardAttribute,
  type CardOut,
  type CardAttributeSetIn,
} from "@/api/endpoints/bankCustomers";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function statusBadgeVariant(status: string): "default" | "secondary" | "destructive" | "outline" {
  if (status === "ACTIVE") return "default";
  if (status === "FROZEN") return "secondary";
  if (status === "CANCELLED") return "destructive";
  return "outline";
}

function expiry(month?: number | null, year?: number | null): string {
  if (!month || !year) return "—";
  return `${String(month).padStart(2, "0")}/${String(year).slice(-2)}`;
}

function fmt(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

// ─── Card attributes sub-panel ────────────────────────────────────────────────

function CardAttributesPanel({ cardId }: { cardId: string }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [type, setType] = useState<"STRING" | "INTEGER" | "DOUBLE" | "DATE_WITH_DAY">("STRING");

  const attrsQ = useQuery({
    queryKey: ["bank-cards", cardId, "attributes"],
    queryFn: () => listCardAttributes(cardId),
    retry: false,
  });

  const setAttrMut = useMutation({
    mutationFn: (body: CardAttributeSetIn) => setCardAttribute(cardId, body),
    onSuccess: () => {
      toast.success("Attribute saved");
      setName("");
      setValue("");
      void qc.invalidateQueries({ queryKey: ["bank-cards", cardId, "attributes"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed"),
  });

  const delAttrMut = useMutation({
    mutationFn: (attrName: string) => deleteCardAttribute(cardId, attrName),
    onSuccess: () => {
      toast.success("Attribute removed");
      void qc.invalidateQueries({ queryKey: ["bank-cards", cardId, "attributes"] });
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Failed"),
  });

  return (
    <div className="space-y-3">
      <h4 className="text-sm font-semibold flex items-center gap-2">
        <Tag className="h-4 w-4" /> Card Attributes
      </h4>

      {attrsQ.isLoading && <Skeleton className="h-8 w-full" />}

      {attrsQ.data && attrsQ.data.length === 0 && (
        <p className="text-sm text-muted-foreground">No attributes.</p>
      )}

      {attrsQ.data && attrsQ.data.map((attr) => (
        <div key={attr.attribute_id} className="flex items-center justify-between rounded border px-3 py-2 text-sm">
          <span>
            <span className="font-medium">{attr.name}</span>
            <span className="text-muted-foreground mx-2">({attr.type})</span>
            <span>{attr.value}</span>
          </span>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 text-muted-foreground"
            onClick={() => delAttrMut.mutate(attr.name)}
          >
            <X className="h-3 w-3" />
          </Button>
        </div>
      ))}

      <div className="flex gap-2 flex-wrap items-end">
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Name</Label>
          <Input className="h-8 w-28 text-xs" value={name} onChange={(e) => setName(e.target.value)} placeholder="name" />
        </div>
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Type</Label>
          <select
            className="h-8 rounded-md border bg-background px-2 text-xs"
            value={type}
            onChange={(e) => setType(e.target.value as typeof type)}
          >
            <option>STRING</option>
            <option>INTEGER</option>
            <option>DOUBLE</option>
            <option>DATE_WITH_DAY</option>
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <Label className="text-xs">Value</Label>
          <Input className="h-8 w-28 text-xs" value={value} onChange={(e) => setValue(e.target.value)} placeholder="value" />
        </div>
        <Button
          size="sm"
          className="h-8"
          disabled={!name.trim() || !value.trim() || setAttrMut.isPending}
          onClick={() => setAttrMut.mutate({ name: name.trim(), type, value: value.trim() })}
        >
          Set
        </Button>
      </div>
    </div>
  );
}

// ─── Card detail dialog ───────────────────────────────────────────────────────

function CardDetailDialog({
  card,
  open,
  onClose,
}: {
  card: CardOut;
  open: boolean;
  onClose: () => void;
}) {
  const qc = useQueryClient();

  const statusMut = useMutation({
    mutationFn: (status: string) =>
      updateCardStatus(card.card_id, { status, expected_version: card.card_version }),
    onSuccess: (updated) => {
      toast.success(`Card ${updated.card_status.toLowerCase()}`);
      void qc.invalidateQueries({ queryKey: ["bank-cards"] });
      onClose();
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : "Status update failed"),
  });

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <CreditCard className="h-5 w-5" />
            {card.brand ?? "Card"} ···· {card.last4 ?? "****"}
          </DialogTitle>
        </DialogHeader>

        <div className="text-sm grid grid-cols-2 gap-2 mb-4">
          <div><span className="text-muted-foreground">ID:</span> <span className="font-mono text-xs break-all">{card.card_id}</span></div>
          <div><span className="text-muted-foreground">Label:</span> {card.label ?? "—"}</div>
          <div><span className="text-muted-foreground">Expiry:</span> {expiry(card.exp_month, card.exp_year)}</div>
          <div><span className="text-muted-foreground">Status:</span> <Badge variant={statusBadgeVariant(card.card_status)}>{card.card_status}</Badge></div>
          <div><span className="text-muted-foreground">Default:</span> {card.is_default ? "Yes" : "No"}</div>
          <div><span className="text-muted-foreground">Created:</span> {fmt(card.created_at)}</div>
        </div>

        {/* Status lifecycle actions */}
        <div className="flex gap-2 flex-wrap mb-4">
          {card.card_status !== "ACTIVE" && (
            <Button
              size="sm"
              variant="outline"
              className="gap-1"
              disabled={statusMut.isPending}
              onClick={() => statusMut.mutate("ACTIVE")}
            >
              <ShieldCheck className="h-4 w-4 text-green-600" /> Activate
            </Button>
          )}
          {card.card_status === "ACTIVE" && (
            <Button
              size="sm"
              variant="outline"
              className="gap-1"
              disabled={statusMut.isPending}
              onClick={() => statusMut.mutate("FROZEN")}
            >
              <ShieldOff className="h-4 w-4 text-blue-600" /> Freeze
            </Button>
          )}
          {card.card_status !== "CANCELLED" && (
            <Button
              size="sm"
              variant="destructive"
              className="gap-1"
              disabled={statusMut.isPending}
              onClick={() => statusMut.mutate("CANCELLED")}
            >
              <XCircle className="h-4 w-4" /> Cancel
            </Button>
          )}
        </div>

        <Separator className="my-2" />
        <CardAttributesPanel cardId={card.card_id} />

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function BankCardsPage() {
  const qc = useQueryClient();
  const [selectedCard, setSelectedCard] = useState<CardOut | null>(null);

  const cardsQ = useQuery({
    queryKey: ["bank-cards"],
    queryFn: listCards,
    retry: false,
  });

  if (cardsQ.error instanceof ApiError && (cardsQ.error.status === 404 || cardsQ.error.status === 503)) {
    return (
      <div className="flex flex-col gap-6">
        <PageHeader title="My Cards" description="OBP CUS-003" />
        <EmptyState
          icon={<CreditCard className="h-8 w-8" />}
          title="Cards not available"
          description="The bank cards feature is not enabled on this platform."
        />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="My Cards"
        description="Manage your bank cards — activate, freeze, or cancel."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => void qc.invalidateQueries({ queryKey: ["bank-cards"] })}
          >
            <RefreshCw className="h-4 w-4 mr-1" /> Refresh
          </Button>
        }
      />

      {cardsQ.isLoading && (
        <div className="space-y-3">
          {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-24 w-full rounded-lg" />)}
        </div>
      )}

      {cardsQ.data?.cards.length === 0 && (
        <EmptyState
          icon={<CreditCard className="h-8 w-8" />}
          title="No cards"
          description="No cards are associated with your account."
        />
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {cardsQ.data?.cards.map((card) => (
          <Card
            key={card.card_id}
            className="cursor-pointer hover:shadow-md transition-shadow"
            onClick={() => setSelectedCard(card)}
          >
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-base flex items-center gap-2">
                  <CreditCard className="h-5 w-5 text-muted-foreground" />
                  {card.brand ?? "Card"}
                </CardTitle>
                <Badge variant={statusBadgeVariant(card.card_status)}>{card.card_status}</Badge>
              </div>
              <CardDescription>
                ···· {card.last4 ?? "****"} · Exp {expiry(card.exp_month, card.exp_year)}
              </CardDescription>
            </CardHeader>
            <CardContent className="text-xs text-muted-foreground">
              {card.label && <p>{card.label}</p>}
              {card.is_default && <p className="font-medium text-primary">Default card</p>}
            </CardContent>
          </Card>
        ))}
      </div>

      {selectedCard && (
        <CardDetailDialog
          card={selectedCard}
          open={!!selectedCard}
          onClose={() => setSelectedCard(null)}
        />
      )}
    </div>
  );
}
