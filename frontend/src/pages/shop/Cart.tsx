import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ShoppingCart,
  Plus,
  Minus,
  Trash2,
  PackagePlus,
} from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
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
  getCarts,
  createCart,
  getCartItems,
  getCartTotal,
  updateCartItemQty,
  removeCartItem,
  deleteCart,
} from "@/api/endpoints/cart";
import type { CartItem } from "@/api/types";

function formatCents(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
  }).format(cents / 100);
}

export function Cart() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [selectedCartId, setSelectedCartId] = useState<string | null>(null);
  const [deleteOpen, setDeleteOpen] = useState(false);

  const cartsQuery = useQuery({
    queryKey: ["carts"],
    queryFn: getCarts,
  });

  const carts = Array.isArray(cartsQuery.data) ? cartsQuery.data : [];
  const activeCarts = carts.filter((c) => c.status === "active");

  // Auto-select first active cart
  const cartId = selectedCartId ?? (activeCarts.length > 0 ? activeCarts[0]!.cart_id : null);

  const itemsQuery = useQuery({
    queryKey: ["cart-items", cartId],
    queryFn: () => getCartItems(cartId!),
    enabled: !!cartId,
  });

  const totalQuery = useQuery({
    queryKey: ["cart-total", cartId],
    queryFn: () => getCartTotal(cartId!),
    enabled: !!cartId,
  });

  const createCartMutation = useMutation({
    mutationFn: () => createCart(),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["carts"] });
      setSelectedCartId(data.cart_id);
      toast.success("New cart created");
    },
    onError: () => {
      toast.error("Failed to create cart");
    },
  });

  const updateQtyMutation = useMutation({
    mutationFn: ({ sku, quantity }: { sku: string; quantity: number }) =>
      updateCartItemQty(cartId!, sku, quantity),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cart-items", cartId] });
      queryClient.invalidateQueries({ queryKey: ["cart-total", cartId] });
    },
    onError: () => {
      toast.error("Failed to update quantity");
    },
  });

  const removeMutation = useMutation({
    mutationFn: (sku: string) => removeCartItem(cartId!, sku),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cart-items", cartId] });
      queryClient.invalidateQueries({ queryKey: ["cart-total", cartId] });
      toast.success("Item removed");
    },
    onError: () => {
      toast.error("Failed to remove item");
    },
  });

  const deleteCartMutation = useMutation({
    mutationFn: () => deleteCart(cartId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["carts"] });
      setSelectedCartId(null);
      setDeleteOpen(false);
      toast.success("Cart deleted");
    },
    onError: () => {
      toast.error("Failed to delete cart");
    },
  });

  const items: CartItem[] = itemsQuery.data?.items ?? [];
  const total = totalQuery.data;

  if (cartsQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-48" />
        <Skeleton className="h-64 w-full rounded-xl" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Cart selector + actions */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          {activeCarts.length > 1 && (
            <Select
              value={cartId ?? ""}
              onValueChange={setSelectedCartId}
            >
              <SelectTrigger className="w-48">
                <SelectValue placeholder="Select cart" />
              </SelectTrigger>
              <SelectContent>
                {activeCarts.map((c) => (
                  <SelectItem key={c.cart_id} value={c.cart_id}>
                    Cart {c.cart_id.slice(0, 8)}...
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
          {activeCarts.length <= 1 && cartId && (
            <span className="text-sm text-muted-foreground">
              Cart {cartId.slice(0, 8)}...
            </span>
          )}
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => createCartMutation.mutate()}
            disabled={createCartMutation.isPending}
          >
            <PackagePlus className="mr-1 h-3.5 w-3.5" />
            New Cart
          </Button>
          {cartId && (
            <Button
              variant="destructive"
              size="sm"
              onClick={() => setDeleteOpen(true)}
            >
              <Trash2 className="mr-1 h-3.5 w-3.5" />
              Delete Cart
            </Button>
          )}
        </div>
      </div>

      {!cartId ? (
        <EmptyState
          icon={<ShoppingCart className="h-8 w-8" />}
          title="No active cart"
          description="Create a new cart to start shopping"
          className="py-16"
        />
      ) : itemsQuery.isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-16 w-full rounded-lg" />
          ))}
        </div>
      ) : items.length === 0 ? (
        <EmptyState
          icon={<ShoppingCart className="h-8 w-8" />}
          title="Cart is empty"
          description="Browse the shop to add items"
          className="py-16"
          action={{
            label: "Browse Shop",
            onClick: () => navigate("/shop"),
          }}
        />
      ) : (
        <>
          {/* Line items */}
          <Card>
            <CardContent className="divide-y p-0">
              {items.map((item) => (
                <div
                  key={item.sku}
                  className="flex items-center gap-4 px-4 py-3"
                >
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium">{item.name}</p>
                    <p className="text-xs text-muted-foreground">
                      SKU: {item.sku}
                    </p>
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {formatCents(item.unit_price_cents)} each
                  </span>
                  <div className="flex items-center rounded-lg border">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 rounded-r-none"
                      onClick={() =>
                        updateQtyMutation.mutate({
                          sku: item.sku,
                          quantity: Math.max(1, item.quantity - 1),
                        })
                      }
                      disabled={updateQtyMutation.isPending}
                    >
                      <Minus className="h-3 w-3" />
                    </Button>
                    <span className="w-8 text-center text-sm">
                      {item.quantity}
                    </span>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 rounded-l-none"
                      onClick={() =>
                        updateQtyMutation.mutate({
                          sku: item.sku,
                          quantity: item.quantity + 1,
                        })
                      }
                      disabled={updateQtyMutation.isPending}
                    >
                      <Plus className="h-3 w-3" />
                    </Button>
                  </div>
                  <span className="w-20 text-right text-sm font-semibold">
                    {formatCents(item.line_total_cents)}
                  </span>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 text-destructive"
                    onClick={() => removeMutation.mutate(item.sku)}
                    disabled={removeMutation.isPending}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Total + checkout */}
          <Card>
            <CardContent className="flex items-center justify-between p-4">
              <div>
                <p className="text-sm text-muted-foreground">Total</p>
                <p className={cn("text-2xl font-bold", totalQuery.isLoading && "animate-pulse")}>
                  {total
                    ? formatCents(total.total_cents, total.currency)
                    : "..."}
                </p>
              </div>
              <Button
                size="lg"
                onClick={() => navigate(`/cart/checkout?cartId=${cartId}`)}
              >
                Proceed to Checkout
              </Button>
            </CardContent>
          </Card>
        </>
      )}

      {/* Delete cart confirmation */}
      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title="Delete Cart"
        description="Are you sure you want to delete this cart? All items will be removed."
        confirmLabel="Delete"
        variant="danger"
        onConfirm={() => deleteCartMutation.mutate()}
        loading={deleteCartMutation.isPending}
      />
    </div>
  );
}
