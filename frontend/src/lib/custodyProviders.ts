// Pure, framework-free helpers for the external custody-provider surface.
// No React / no network — safe to unit-test in isolation (vitest).
//
// Covers: provider status → badge label + severity; withdrawal approval
// status → an ordered stepper model; provider kind → display label + icon
// key; and a human "who custodies" attestation label.

export type ProviderKind = "internal" | "fireblocks" | "bitgo";
export type ProviderStatus = "healthy" | "degraded" | "down" | "not_connected";
export type ApprovalStatus =
  | "pending_approval"
  | "approved"
  | "signed"
  | "broadcast"
  | "rejected";

export type BadgeSeverity = "success" | "warning" | "danger" | "neutral";

export interface StatusBadge {
  label: string;
  severity: BadgeSeverity;
}

/** Map a provider status → a display badge (label + severity). */
export function providerStatusBadge(
  status: ProviderStatus | string | null | undefined,
): StatusBadge {
  switch (status) {
    case "healthy":
      return { label: "Healthy", severity: "success" };
    case "degraded":
      return { label: "Degraded", severity: "warning" };
    case "down":
      return { label: "Down", severity: "danger" };
    case "not_connected":
      return { label: "Not connected", severity: "neutral" };
    default:
      return { label: "Unknown", severity: "neutral" };
  }
}

export interface ProviderDisplay {
  /** Human provider name. */
  label: string;
  /** A stable icon key the UI maps to a concrete icon (no icon dep here). */
  iconKey: "internal" | "fireblocks" | "bitgo" | "external";
  /** True when the vault is custodied by a third-party qualified custodian. */
  external: boolean;
}

/** Map a provider kind → display label + icon key. */
export function providerKindDisplay(
  kind: ProviderKind | string | null | undefined,
): ProviderDisplay {
  switch (kind) {
    case "internal":
      return { label: "Internal gateway", iconKey: "internal", external: false };
    case "fireblocks":
      return { label: "Fireblocks", iconKey: "fireblocks", external: true };
    case "bitgo":
      return { label: "BitGo", iconKey: "bitgo", external: true };
    default:
      return {
        label: kind ? String(kind) : "Unknown",
        iconKey: "external",
        external: true,
      };
  }
}

/**
 * A human "who custodies your assets" attestation label, e.g.
 *   "Custodied by Fireblocks" / "Self-custodied (internal gateway)".
 */
export function providerAttestationLabel(
  kind: ProviderKind | string | null | undefined,
): string {
  const d = providerKindDisplay(kind);
  if (!d.external) return "Self-custodied (internal gateway)";
  return `Custodied by ${d.label}`;
}

// ─── Withdrawal approval stepper ─────────────────────────────────
// The happy path is an ORDERED progression:
//   pending_approval → approved → signed → broadcast
// "rejected" is a terminal off-path state (not a step in the ladder).

export const APPROVAL_STEP_ORDER: readonly ApprovalStatus[] = [
  "pending_approval",
  "approved",
  "signed",
  "broadcast",
] as const;

const APPROVAL_STEP_LABELS: Record<
  Exclude<ApprovalStatus, "rejected">,
  string
> = {
  pending_approval: "Pending approval",
  approved: "Approved",
  signed: "Signed",
  broadcast: "Broadcast",
};

export type StepState = "done" | "current" | "upcoming" | "rejected";

export interface ApprovalStep {
  key: ApprovalStatus;
  label: string;
  state: StepState;
}

export interface ApprovalStepperModel {
  steps: ApprovalStep[];
  /** True when the withdrawal was rejected (terminal, off the ladder). */
  rejected: boolean;
  /** True when broadcast (fully complete). */
  complete: boolean;
  /** Index of the current step in APPROVAL_STEP_ORDER (-1 if rejected/unknown). */
  currentIndex: number;
}

/**
 * Build an ordered stepper model from a withdrawal-approval status.
 * Unknown statuses degrade to "everything upcoming" (index 0 pending).
 */
export function approvalStepper(
  status: ApprovalStatus | string | null | undefined,
): ApprovalStepperModel {
  const rejected = status === "rejected";
  const idx = APPROVAL_STEP_ORDER.indexOf(status as ApprovalStatus);
  const currentIndex = rejected ? -1 : idx;

  const steps: ApprovalStep[] = APPROVAL_STEP_ORDER.map((key, i) => {
    let state: StepState;
    if (rejected) {
      // On rejection, the first step is marked rejected, the rest upcoming.
      state = i === 0 ? "rejected" : "upcoming";
    } else if (currentIndex < 0) {
      // Unknown status → nothing reached yet.
      state = i === 0 ? "current" : "upcoming";
    } else if (i < currentIndex) {
      state = "done";
    } else if (i === currentIndex) {
      // The final step "broadcast" is a completion, render it as done.
      state = key === "broadcast" ? "done" : "current";
    } else {
      state = "upcoming";
    }
    return {
      key,
      label: APPROVAL_STEP_LABELS[key as Exclude<ApprovalStatus, "rejected">],
      state,
    };
  });

  return {
    steps,
    rejected,
    complete: !rejected && status === "broadcast",
    currentIndex,
  };
}

/** A short human label for an approval status (incl. rejected). */
export function approvalStatusLabel(
  status: ApprovalStatus | string | null | undefined,
): string {
  if (status === "rejected") return "Rejected";
  const key = status as Exclude<ApprovalStatus, "rejected">;
  return APPROVAL_STEP_LABELS[key] ?? "Unknown";
}
