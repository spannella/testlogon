/**
 * CatalogDepthPage (PRD-015)
 *
 * Standalone admin page that wraps ProductDepthPanel for a given catalog item.
 * Route: /shop/admin/catalog/depth/:itemId
 *
 * Gated by VITE_PRODUCT_DEPTH_ENABLED="true".  When the flag is off, a
 * placeholder is shown so the route doesn't 404.
 */

import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Boxes } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

import { listCategories } from "@/api/endpoints/productDepth";
import { ProductDepthPanel } from "../ProductDepthPanel";

const DEPTH_ENABLED =
  (import.meta as any).env?.VITE_PRODUCT_DEPTH_ENABLED === "true";

export default function CatalogDepthPage() {
  const { itemId = "" } = useParams<{ itemId: string }>();

  // Resolve item name from the category listing (best-effort; name is cosmetic).
  const catsQuery = useQuery({
    queryKey: ["catalogDepth", "categories"],
    queryFn: async () => (await listCategories()).items,
    staleTime: 60_000,
    enabled: DEPTH_ENABLED,
  });

  const itemName = (() => {
    if (!catsQuery.data) return undefined;
    // listCategories returns categories, not items — we don't have the name
    // here without a separate item lookup. Return undefined so ProductDepthPanel
    // just shows the ID.
    return undefined;
  })();

  if (!DEPTH_ENABLED) {
    return (
      <div className="mx-auto max-w-3xl p-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Boxes className="h-5 w-5" /> Catalog Depth (disabled)
            </CardTitle>
            <CardDescription>
              Set{" "}
              <code className="font-mono">VITE_PRODUCT_DEPTH_ENABLED=true</code>{" "}
              in your frontend environment to enable this feature.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Item ID: <span className="font-mono">{itemId || "(none)"}</span>
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!itemId) {
    return (
      <div className="mx-auto max-w-3xl p-6">
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            No item ID provided. Navigate here from the catalog admin with a
            valid item ID.
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="mx-auto w-full max-w-5xl space-y-4 p-4 md:p-6">
      <div className="flex items-center gap-3">
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          onClick={() => history.back()}
          title="Go back"
        >
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div className="space-y-0.5">
          <h1 className="flex items-center gap-2 text-xl font-semibold">
            <Boxes className="h-5 w-5" /> Catalog Depth
          </h1>
          <p className="font-mono text-xs text-muted-foreground">{itemId}</p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {catsQuery.isLoading ? (
              <Skeleton className="h-5 w-48" />
            ) : (
              "Product depth attributes"
            )}
          </CardTitle>
          <CardDescription>
            Manage feature categories, variants, bundle composition, and product
            associations for this item.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ProductDepthPanel itemId={itemId} itemName={itemName} />
        </CardContent>
      </Card>
    </div>
  );
}
