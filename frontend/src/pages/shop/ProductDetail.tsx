import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  ArrowLeft,
  Package,
  ShoppingCart,
  Star,
  Minus,
  Plus,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import {
  getCategoryItems,
  getItemReviews,
  createReview,
  getCarts,
  createCart,
  addCartItem,
} from "@/api/endpoints/cart";
import type { CatalogItem } from "@/api/types";

function formatPrice(cents: number, currency = "USD"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
  }).format(cents / 100);
}

const reviewSchema = z.object({
  rating: z.number().min(1).max(5),
  title: z.string().optional(),
  body: z.string().optional(),
});

type ReviewFormValues = z.infer<typeof reviewSchema>;

export default function ProductDetail() {
  const { categoryId, itemId } = useParams<{ categoryId: string; itemId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [quantity, setQuantity] = useState(1);
  const [hoverRating, setHoverRating] = useState(0);
  const [activeImageIndex, setActiveImageIndex] = useState(0);

  const form = useForm<ReviewFormValues>({
    resolver: zodResolver(reviewSchema),
    defaultValues: { rating: 0, title: "", body: "" },
  });

  const itemsQuery = useQuery({
    queryKey: ["catalog", "items", categoryId],
    queryFn: () => getCategoryItems(categoryId!),
    enabled: !!categoryId,
  });

  const item: CatalogItem | undefined = (itemsQuery.data?.items ?? []).find(
    (i) => i.item_id === itemId,
  );

  const reviewsQuery = useQuery({
    queryKey: ["catalog", "reviews", itemId],
    queryFn: () => getItemReviews(itemId!),
    enabled: !!itemId,
  });

  const cartsQuery = useQuery({
    queryKey: ["carts"],
    queryFn: getCarts,
  });

  const addToCartMutation = useMutation({
    mutationFn: async () => {
      if (!item) throw new Error("No item");
      const carts = Array.isArray(cartsQuery.data) ? cartsQuery.data : [];
      let activeCart = carts.find((c) => c.status === "active");
      if (!activeCart) {
        activeCart = await createCart();
      }
      return addCartItem(activeCart.cart_id, {
        sku: item.item_id,
        name: item.name,
        quantity,
        unit_price_cents: item.price_cents,
        image_url: item.image_urls?.[0],
        category_id: categoryId,
        item_id: item.item_id,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["carts"] });
      toast.success(`Added ${quantity} x ${item?.name ?? "item"} to cart`);
    },
    onError: () => {
      toast.error("Failed to add to cart. Make sure you have an active cart.");
    },
  });

  const reviewMutation = useMutation({
    mutationFn: (values: ReviewFormValues) =>
      createReview(itemId!, values),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["catalog", "reviews", itemId] });
      form.reset({ rating: 0, title: "", body: "" });
      toast.success("Review submitted");
    },
    onError: () => {
      toast.error("Failed to submit review");
    },
  });

  const reviews = reviewsQuery.data?.items ?? [];
  const watchedRating = form.watch("rating");

  if (itemsQuery.isLoading) {
    return (
      <div className="mx-auto max-w-3xl space-y-6 p-4 sm:p-6">
        <Skeleton className="h-8 w-32" />
        <div className="grid gap-6 sm:grid-cols-2">
          <Skeleton className="h-64 rounded-xl" />
          <div className="space-y-3">
            <Skeleton className="h-8 w-48" />
            <Skeleton className="h-6 w-24" />
            <Skeleton className="h-20 w-full" />
          </div>
        </div>
      </div>
    );
  }

  if (!item) {
    return (
      <div className="mx-auto max-w-3xl p-4 sm:p-6">
        <Button variant="ghost" size="sm" onClick={() => navigate("/shop")}>
          <ArrowLeft className="mr-1 h-4 w-4" />
          Back to shop
        </Button>
        <div className="mt-8 text-center">
          <Package className="mx-auto h-12 w-12 text-muted-foreground" />
          <p className="mt-2 text-muted-foreground">Product not found</p>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6 p-4 sm:p-6">
      {/* Back button */}
      <Button variant="ghost" size="sm" onClick={() => navigate("/shop")}>
        <ArrowLeft className="mr-1 h-4 w-4" />
        Back to shop
      </Button>

      {/* Product info */}
      <div className="grid gap-6 sm:grid-cols-2">
        {/* Image gallery */}
        <div className="space-y-2">
          <div className="flex aspect-square items-center justify-center rounded-xl bg-muted overflow-hidden">
            {item.image_urls.length > 0 ? (
              <img
                src={item.image_urls[activeImageIndex]}
                alt={item.name}
                className="h-full w-full object-cover"
              />
            ) : (
              <Package className="h-16 w-16 text-muted-foreground/50" />
            )}
          </div>
          {item.image_urls.length > 1 && (
            <div className="flex gap-2 overflow-x-auto pb-1">
              {item.image_urls.map((url, i) => (
                <button
                  key={i}
                  onClick={() => setActiveImageIndex(i)}
                  className={`h-14 w-14 shrink-0 overflow-hidden rounded-lg border-2 transition-colors ${
                    i === activeImageIndex
                      ? "border-primary"
                      : "border-transparent opacity-60 hover:opacity-100"
                  }`}
                >
                  <img src={url} alt={`${item.name} ${i + 1}`} className="h-full w-full object-cover" />
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Details */}
        <div className="space-y-4">
          <div>
            <h1 className="text-2xl font-bold">{item.name}</h1>
            <p className="mt-1 text-2xl font-semibold text-primary">
              {formatPrice(item.price_cents, item.currency)}
            </p>
          </div>

          {item.description && (
            <p className="text-sm text-muted-foreground">{item.description}</p>
          )}

          {/* Attributes */}
          {Object.keys(item.attributes).length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(item.attributes).map(([key, value]) => (
                <Badge key={key} variant="outline" className="text-xs">
                  {key}: {String(value)}
                </Badge>
              ))}
            </div>
          )}

          <Separator />

          {/* Quantity + Add to cart */}
          <div className="flex items-center gap-3">
            <div className="flex items-center rounded-lg border">
              <Button
                variant="ghost"
                size="icon"
                className="h-9 w-9 rounded-r-none"
                onClick={() => setQuantity((q) => Math.max(1, q - 1))}
              >
                <Minus className="h-3.5 w-3.5" />
              </Button>
              <Input
                type="number"
                min={1}
                value={quantity}
                onChange={(e) => setQuantity(Math.max(1, Number(e.target.value)))}
                className="h-9 w-14 rounded-none border-x-0 text-center [appearance:textfield] [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:appearance-none"
              />
              <Button
                variant="ghost"
                size="icon"
                className="h-9 w-9 rounded-l-none"
                onClick={() => setQuantity((q) => q + 1)}
              >
                <Plus className="h-3.5 w-3.5" />
              </Button>
            </div>
            <Button
              className="flex-1"
              onClick={() => addToCartMutation.mutate()}
              disabled={addToCartMutation.isPending}
            >
              <ShoppingCart className="mr-2 h-4 w-4" />
              {addToCartMutation.isPending ? "Adding..." : "Add to Cart"}
            </Button>
          </div>
        </div>
      </div>

      <Separator />

      {/* Reviews */}
      <Card>
        <CardHeader>
          <CardTitle>
            Reviews ({reviews.length})
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {reviews.length === 0 ? (
            <p className="text-sm text-muted-foreground">No reviews yet. Be the first to review!</p>
          ) : (
            <div className="space-y-3">
              {reviews.map((review) => (
                <div key={review.review_id} className="rounded-lg border p-3">
                  <div className="flex items-center gap-2">
                    <div className="flex">
                      {Array.from({ length: 5 }).map((_, i) => (
                        <Star
                          key={i}
                          className={`h-3.5 w-3.5 ${
                            i < review.rating
                              ? "fill-yellow-400 text-yellow-400"
                              : "text-muted-foreground/30"
                          }`}
                        />
                      ))}
                    </div>
                    {review.reviewer && (
                      <span className="text-xs text-muted-foreground">
                        by {review.reviewer}
                      </span>
                    )}
                  </div>
                  {review.title && (
                    <p className="mt-1 text-sm font-medium">{review.title}</p>
                  )}
                  {review.body && (
                    <p className="mt-0.5 text-sm text-muted-foreground">{review.body}</p>
                  )}
                </div>
              ))}
            </div>
          )}

          <Separator />

          {/* Write a review */}
          <form
            onSubmit={form.handleSubmit((v) => reviewMutation.mutate(v))}
            className="space-y-3"
          >
            <h4 className="text-sm font-medium">Write a Review</h4>
            <div className="space-y-1.5">
              <Label>Rating</Label>
              <div className="flex gap-1">
                {Array.from({ length: 5 }).map((_, i) => {
                  const starValue = i + 1;
                  const active = starValue <= (hoverRating || watchedRating);
                  return (
                    <button
                      key={i}
                      type="button"
                      onMouseEnter={() => setHoverRating(starValue)}
                      onMouseLeave={() => setHoverRating(0)}
                      onClick={() => form.setValue("rating", starValue)}
                      className="p-0.5"
                    >
                      <Star
                        className={`h-5 w-5 transition-colors ${
                          active
                            ? "fill-yellow-400 text-yellow-400"
                            : "text-muted-foreground/30"
                        }`}
                      />
                    </button>
                  );
                })}
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="review-title">Title (optional)</Label>
              <Input id="review-title" {...form.register("title")} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="review-body">Review (optional)</Label>
              <Textarea id="review-body" rows={3} {...form.register("body")} />
            </div>
            <Button
              type="submit"
              size="sm"
              disabled={watchedRating === 0 || reviewMutation.isPending}
            >
              {reviewMutation.isPending ? "Submitting..." : "Submit Review"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
