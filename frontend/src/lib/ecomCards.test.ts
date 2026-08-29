import { describe, expect, it } from "vitest";
import {
  buildOrderCardPayload,
  buildProductCardPayload,
  formatPriceCents,
  orderCardPreview,
  orderModeLabel,
  productCardPreview,
  type OrderCardSource,
} from "./ecomCards";
import type { CatalogItem } from "@/api/types";

const item: CatalogItem = {
  category_id: "cat-1",
  item_id: "it-1",
  name: "Blue Widget",
  description: "A widget",
  price_cents: 1299,
  currency: "USD",
  image_urls: ["https://img/one.png", "https://img/two.png"],
  attributes: {},
  created_at: "2026-01-01",
  updated_at: "2026-01-01",
  stock_status: "in_stock",
  low_stock_threshold: 1,
};

describe("buildProductCardPayload", () => {
  it("projects the catalog item into a shareable payload (first image, cents)", () => {
    const p = buildProductCardPayload(item);
    expect(p.product_id).toBe("it-1");
    expect(p.category_id).toBe("cat-1");
    expect(p.title).toBe("Blue Widget");
    expect(p.price_cents).toBe(1299);
    expect(p.currency).toBe("USD");
    expect(p.image).toBe("https://img/one.png");
    expect(p.in_stock).toBe(true);
  });

  it("marks out_of_stock status as not in stock", () => {
    const p = buildProductCardPayload({ ...item, stock_status: "out_of_stock" });
    expect(p.in_stock).toBe(false);
  });

  it("marks a zero stock_count as not in stock", () => {
    const p = buildProductCardPayload({ ...item, stock_status: "", stock_count: 0 });
    expect(p.in_stock).toBe(false);
  });

  it("defaults currency to USD and image to undefined when absent", () => {
    const p = buildProductCardPayload({ ...item, currency: "", image_urls: [] });
    expect(p.currency).toBe("USD");
    expect(p.image).toBeUndefined();
  });
});

const order: OrderCardSource = {
  order_id: "ord-9",
  status: "paid",
  lifecycle_status: "shipped",
  currency: "USD",
  amount_cents: 4599,
  line_item_count: 3,
  line_items: [
    { name: "Blue Widget", quantity: 2 },
    { name: "Red Gadget", quantity: 1 },
  ],
};

describe("buildOrderCardPayload — PII choke point", () => {
  it("receipt mode carries item summary + status but NO amount", () => {
    const p = buildOrderCardPayload(order, "receipt");
    expect(p.mode).toBe("receipt");
    expect(p.status).toBe("shipped");
    expect(p.items).toHaveLength(2);
    expect(p.items[0]).toEqual({ name: "Blue Widget", quantity: 2 });
    expect(p.item_count).toBe(3);
    // Receipt mode omits the money total.
    expect(p.amount_cents).toBeUndefined();
  });

  it("receipt mode NEVER leaks buyer name / address even if present on the source", () => {
    // Attacker-ish source: extra PII-looking fields must be ignored by construction.
    const dirty = {
      ...order,
      buyer_name: "Jane Buyer",
      ship_to: "123 Secret St",
      address_line1: "123 Secret St",
      email: "jane@example.com",
    } as unknown as OrderCardSource;
    const p = buildOrderCardPayload(dirty, "receipt");
    const serialized = JSON.stringify(p);
    expect(serialized).not.toContain("Jane Buyer");
    expect(serialized).not.toContain("Secret St");
    expect(serialized).not.toContain("jane@example.com");
    // and the payload has no such keys
    expect(Object.keys(p)).not.toContain("buyer_name");
    expect(Object.keys(p)).not.toContain("ship_to");
    expect(Object.keys(p)).not.toContain("address_line1");
    expect(Object.keys(p)).not.toContain("email");
  });

  it("gift mode includes the amount + item summary", () => {
    const p = buildOrderCardPayload(order, "gift");
    expect(p.mode).toBe("gift");
    expect(p.amount_cents).toBe(4599);
    expect(p.items).toHaveLength(2);
  });

  it("recommendation mode includes the amount + item summary", () => {
    const p = buildOrderCardPayload(order, "recommendation");
    expect(p.mode).toBe("recommendation");
    expect(p.amount_cents).toBe(4599);
  });

  it("falls back to summed item quantities for item_count when the row count is absent", () => {
    const p = buildOrderCardPayload(
      { ...order, line_item_count: undefined },
      "receipt",
    );
    expect(p.item_count).toBe(3); // 2 + 1
  });
});

describe("previews + labels + price format", () => {
  it("productCardPreview uses the title", () => {
    expect(productCardPreview({ title: "Blue Widget" })).toBe("[Product: Blue Widget]");
    expect(productCardPreview({})).toBe("[Product]");
  });

  it("orderCardPreview shows a single item name or an N-items count", () => {
    expect(orderCardPreview({ order_items: [{ name: "Blue Widget", quantity: 1 }] })).toBe(
      "[Order: Blue Widget]",
    );
    expect(
      orderCardPreview({
        order_items: [
          { name: "A", quantity: 1 },
          { name: "B", quantity: 1 },
        ],
        order_item_count: 2,
      }),
    ).toBe("[Order: 2 items]");
    expect(orderCardPreview({})).toBe("[Order]");
  });

  it("orderModeLabel maps modes to labels", () => {
    expect(orderModeLabel("receipt")).toBe("Receipt");
    expect(orderModeLabel("gift")).toBe("Gift");
    expect(orderModeLabel("recommendation")).toBe("Recommendation");
    expect(orderModeLabel("nope")).toBe("Order");
  });

  it("formatPriceCents formats integer cents as currency", () => {
    expect(formatPriceCents(1299, "USD")).toBe("$12.99");
    expect(formatPriceCents(null)).toBe("");
  });
});
