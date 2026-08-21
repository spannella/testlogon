import { describe, expect, it } from "vitest";

import {
  providerStatusBadge,
  providerKindDisplay,
  providerAttestationLabel,
  approvalStepper,
  approvalStatusLabel,
  APPROVAL_STEP_ORDER,
} from "@/lib/custodyProviders";

describe("providerStatusBadge", () => {
  it("maps each known status to a label + severity", () => {
    expect(providerStatusBadge("healthy")).toEqual({ label: "Healthy", severity: "success" });
    expect(providerStatusBadge("degraded")).toEqual({ label: "Degraded", severity: "warning" });
    expect(providerStatusBadge("down")).toEqual({ label: "Down", severity: "danger" });
    expect(providerStatusBadge("not_connected")).toEqual({
      label: "Not connected",
      severity: "neutral",
    });
  });

  it("degrades unknown / nullish statuses to neutral Unknown", () => {
    expect(providerStatusBadge("weird")).toEqual({ label: "Unknown", severity: "neutral" });
    expect(providerStatusBadge(undefined)).toEqual({ label: "Unknown", severity: "neutral" });
    expect(providerStatusBadge(null)).toEqual({ label: "Unknown", severity: "neutral" });
  });
});

describe("providerKindDisplay", () => {
  it("maps internal (non-external)", () => {
    expect(providerKindDisplay("internal")).toEqual({
      label: "Internal gateway",
      iconKey: "internal",
      external: false,
    });
  });

  it("maps external custodians", () => {
    expect(providerKindDisplay("fireblocks")).toEqual({
      label: "Fireblocks",
      iconKey: "fireblocks",
      external: true,
    });
    expect(providerKindDisplay("bitgo")).toEqual({
      label: "BitGo",
      iconKey: "bitgo",
      external: true,
    });
  });

  it("degrades unknown kinds to an external label with the raw name", () => {
    expect(providerKindDisplay("copper")).toEqual({
      label: "copper",
      iconKey: "external",
      external: true,
    });
    expect(providerKindDisplay(undefined)).toEqual({
      label: "Unknown",
      iconKey: "external",
      external: true,
    });
  });
});

describe("providerAttestationLabel", () => {
  it("self-custodied for internal", () => {
    expect(providerAttestationLabel("internal")).toBe("Self-custodied (internal gateway)");
  });
  it("names the external custodian", () => {
    expect(providerAttestationLabel("fireblocks")).toBe("Custodied by Fireblocks");
    expect(providerAttestationLabel("bitgo")).toBe("Custodied by BitGo");
  });
  it("degrades unknown to Custodied by <raw>", () => {
    expect(providerAttestationLabel("copper")).toBe("Custodied by copper");
  });
});

describe("approvalStepper", () => {
  it("exposes the ordered ladder", () => {
    expect(APPROVAL_STEP_ORDER).toEqual([
      "pending_approval",
      "approved",
      "signed",
      "broadcast",
    ]);
  });

  it("pending_approval → first step current, rest upcoming", () => {
    const m = approvalStepper("pending_approval");
    expect(m.rejected).toBe(false);
    expect(m.complete).toBe(false);
    expect(m.currentIndex).toBe(0);
    expect(m.steps.map((s) => s.state)).toEqual([
      "current",
      "upcoming",
      "upcoming",
      "upcoming",
    ]);
  });

  it("approved → prior done, current on approved", () => {
    const m = approvalStepper("approved");
    expect(m.currentIndex).toBe(1);
    expect(m.steps.map((s) => s.state)).toEqual([
      "done",
      "current",
      "upcoming",
      "upcoming",
    ]);
  });

  it("signed → two done, current on signed", () => {
    const m = approvalStepper("signed");
    expect(m.steps.map((s) => s.state)).toEqual([
      "done",
      "done",
      "current",
      "upcoming",
    ]);
  });

  it("broadcast → all done + complete", () => {
    const m = approvalStepper("broadcast");
    expect(m.complete).toBe(true);
    expect(m.rejected).toBe(false);
    expect(m.steps.map((s) => s.state)).toEqual(["done", "done", "done", "done"]);
  });

  it("rejected → terminal off-ladder", () => {
    const m = approvalStepper("rejected");
    expect(m.rejected).toBe(true);
    expect(m.complete).toBe(false);
    expect(m.currentIndex).toBe(-1);
    expect(m.steps[0]?.state).toBe("rejected");
    expect(m.steps.slice(1).every((s) => s.state === "upcoming")).toBe(true);
  });

  it("unknown status degrades to first-step current", () => {
    const m = approvalStepper("mystery");
    expect(m.rejected).toBe(false);
    expect(m.currentIndex).toBe(-1);
    expect(m.steps[0]?.state).toBe("current");
  });

  it("labels every step", () => {
    const m = approvalStepper("pending_approval");
    expect(m.steps.map((s) => s.label)).toEqual([
      "Pending approval",
      "Approved",
      "Signed",
      "Broadcast",
    ]);
  });
});

describe("approvalStatusLabel", () => {
  it("labels each status incl. rejected", () => {
    expect(approvalStatusLabel("pending_approval")).toBe("Pending approval");
    expect(approvalStatusLabel("approved")).toBe("Approved");
    expect(approvalStatusLabel("signed")).toBe("Signed");
    expect(approvalStatusLabel("broadcast")).toBe("Broadcast");
    expect(approvalStatusLabel("rejected")).toBe("Rejected");
    expect(approvalStatusLabel("nope")).toBe("Unknown");
  });
});
