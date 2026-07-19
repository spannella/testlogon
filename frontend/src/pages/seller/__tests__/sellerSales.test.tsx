import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { render, screen } from "@testing-library/react";

import {
  isOpenFulfilment,
  prettySellerStatus,
  formatShipTo,
} from "@/api/endpoints/sellerSales";
import {
  OrderShipmentTracking,
  ShipmentTrackingCard,
} from "@/components/shared/ShipmentTracking";
import type { OrderShipment } from "@/api/endpoints/orderLifecycle";

describe("sellerSales helpers", () => {
  it("isOpenFulfilment is true for pre-ship stages, false once shipped/closed", () => {
    for (const s of ["created", "approved", "allocated", "picking", "packed", "held", "backorder"]) {
      expect(isOpenFulfilment(s)).toBe(true);
    }
    for (const s of ["shipped", "completed", "cancelled", "returned"]) {
      expect(isOpenFulfilment(s)).toBe(false);
    }
  });

  it("prettySellerStatus title-cases and handles nullish", () => {
    expect(prettySellerStatus("shipped")).toBe("Shipped");
    expect(prettySellerStatus(null)).toBe("—");
    expect(prettySellerStatus(undefined)).toBe("—");
  });

  it("formatShipTo composes a one-line address and tolerates empties", () => {
    expect(formatShipTo({})).toBe("");
    const line = formatShipTo({
      name: "Alice Buyer",
      line1: "1 Main St",
      city: "Springfield",
      state: "IL",
      postal_code: "62704",
      country: "US",
    });
    expect(line).toContain("Alice Buyer");
    expect(line).toContain("1 Main St");
    expect(line).toContain("Springfield, IL, 62704");
    expect(line).toContain("US");
  });
});

const SHIPPED: OrderShipment = {
  ship_group_id: "sg_1",
  carrier: "ups",
  tracking_number: "1Z999AA10123456784",
  tracking_url: "https://www.ups.com/track?tracknum=1Z999AA10123456784",
  status: "in_transit",
  last_event: { status: "in_transit", description: "Departed facility", ts: 1784444933 },
  updated_at: 1784444933,
};

describe("ShipmentTracking render", () => {
  it("renders carrier, tracking number as a link, and status", () => {
    render(
      <MemoryRouter>
        <ShipmentTrackingCard shipment={SHIPPED} />
      </MemoryRouter>,
    );
    expect(screen.getByTestId("shipment-carrier").textContent?.toUpperCase()).toContain("UPS");
    const link = screen.getByTestId("shipment-tracking-link") as HTMLAnchorElement;
    expect(link.getAttribute("href")).toBe(SHIPPED.tracking_url);
    expect(link.textContent).toContain("1Z999AA10123456784");
    expect(screen.getByTestId("shipment-status").textContent).toMatch(/transit/i);
  });

  it("renders a plain number (no link) when no tracking_url", () => {
    render(
      <MemoryRouter>
        <ShipmentTrackingCard shipment={{ ...SHIPPED, tracking_url: "" }} />
      </MemoryRouter>,
    );
    expect(screen.queryByTestId("shipment-tracking-link")).toBeNull();
    expect(screen.getByTestId("shipment-tracking-number").textContent).toContain("1Z999AA10123456784");
  });

  it("OrderShipmentTracking returns nothing when there is no shipment data", () => {
    const { container } = render(
      <MemoryRouter>
        <OrderShipmentTracking shipments={[]} fulfillmentStatus={null} />
      </MemoryRouter>,
    );
    expect(container.querySelector('[data-testid="order-shipment-tracking"]')).toBeNull();
  });

  it("OrderShipmentTracking renders the block + fulfilment status when populated", () => {
    render(
      <MemoryRouter>
        <OrderShipmentTracking shipments={[SHIPPED]} fulfillmentStatus="shipped" />
      </MemoryRouter>,
    );
    expect(screen.getByTestId("order-shipment-tracking")).toBeTruthy();
    expect(screen.getByTestId("shipment-carrier")).toBeTruthy();
  });
});
