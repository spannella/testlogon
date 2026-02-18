import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import RootRoleManagementPage, { validateAdminProfileInput } from "../RootRoleManagementPage";

const grantAdminRole = vi.fn();
const revokeAdminRole = vi.fn();
const updateAdminProfile = vi.fn();
const listRoleAudit = vi.fn();

vi.mock("@/api/endpoints/adminRoles", () => ({
  grantAdminRole: (...args: unknown[]) => grantAdminRole(...args),
  revokeAdminRole: (...args: unknown[]) => revokeAdminRole(...args),
  updateAdminProfile: (...args: unknown[]) => updateAdminProfile(...args),
  listRoleAudit: (...args: unknown[]) => listRoleAudit(...args),
}));

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: { accessToken: string | null }) => unknown) => selector({ accessToken: null }),
}));

vi.mock("sonner", () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}));

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <RootRoleManagementPage />
    </QueryClientProvider>,
  );
}

describe("RootRoleManagementPage profile validation", () => {
  it("validates general/scoped profile combinations", () => {
    expect(validateAdminProfileInput("general", [])).toBeNull();
    expect(validateAdminProfileInput("general", ["auth_support"]))
      .toContain("General admins cannot have scoped permissions");
    expect(validateAdminProfileInput("scoped", [])).toContain("Scoped admins must include at least one scope");
    expect(validateAdminProfileInput("scoped", ["billing_support"]))
      .toBeNull();
  });
});

describe("RootRoleManagementPage grant admin payloads", () => {
  beforeEach(() => {
    grantAdminRole.mockResolvedValue({ ok: true, target_user_sub: "u1", role: "admin", event_id: "evt1" });
    revokeAdminRole.mockResolvedValue({ ok: true, target_user_sub: "u1", role: "user", event_id: "evt2" });
    updateAdminProfile.mockResolvedValue({ ok: true, target_user_sub: "u1", role: "admin", event_id: "evt3" });
    listRoleAudit.mockResolvedValue({ items: [] });
    grantAdminRole.mockClear();
  });

  it.each([
    {
      label: "general admin",
      setup: () => {},
      expected: {
        target_user_sub: "target_1",
        role: "admin",
        reason: "ops",
        admin_profile_type: "general",
        admin_scopes: undefined,
      },
    },
    {
      label: "auth-support scoped admin",
      setup: () => {
        const grantCard = screen.getByText("Grant admin role").closest("div")?.parentElement?.parentElement as HTMLElement;
        const q = within(grantCard);
        fireEvent.change(q.getByLabelText("Admin profile mode"), { target: { value: "scoped" } });
        fireEvent.click(q.getByLabelText(/Auth support/i));
      },
      expected: {
        target_user_sub: "target_1",
        role: "admin",
        reason: "ops",
        admin_profile_type: "scoped",
        admin_scopes: ["auth_support"],
      },
    },
    {
      label: "billing scoped admin",
      setup: () => {
        const grantCard = screen.getByText("Grant admin role").closest("div")?.parentElement?.parentElement as HTMLElement;
        const q = within(grantCard);
        fireEvent.change(q.getByLabelText("Admin profile mode"), { target: { value: "scoped" } });
        fireEvent.click(q.getByLabelText(/Billing support/i));
      },
      expected: {
        target_user_sub: "target_1",
        role: "admin",
        reason: "ops",
        admin_profile_type: "scoped",
        admin_scopes: ["billing_support"],
      },
    },
    {
      label: "content moderation scoped admin",
      setup: () => {
        const grantCard = screen.getByText("Grant admin role").closest("div")?.parentElement?.parentElement as HTMLElement;
        const q = within(grantCard);
        fireEvent.change(q.getByLabelText("Admin profile mode"), { target: { value: "scoped" } });
        fireEvent.click(q.getByLabelText(/Content moderation/i));
      },
      expected: {
        target_user_sub: "target_1",
        role: "admin",
        reason: "ops",
        admin_profile_type: "scoped",
        admin_scopes: ["content_moderation"],
      },
    },
  ])("submits $label", async ({ setup, expected }) => {
    renderPage();

    const grantCard = screen.getByText("Grant admin role").closest("div")?.parentElement?.parentElement as HTMLElement;
    const q = within(grantCard);

    fireEvent.change(q.getByLabelText("Target user_sub"), { target: { value: "target_1" } });
    fireEvent.change(q.getByLabelText("Reason"), { target: { value: "ops" } });
    setup();

    fireEvent.click(q.getByRole("button", { name: "Grant admin" }));

    await waitFor(() => {
      expect(grantAdminRole).toHaveBeenCalledWith(expected);
    });
  });

  it("blocks invalid client-side combination for scoped mode without scopes", async () => {
    renderPage();
    const grantCard = screen.getByText("Grant admin role").closest("div")?.parentElement?.parentElement as HTMLElement;
    const q = within(grantCard);
    fireEvent.change(q.getByLabelText("Target user_sub"), { target: { value: "target_1" } });
    fireEvent.change(q.getByLabelText("Reason"), { target: { value: "ops" } });
    fireEvent.change(q.getByLabelText("Admin profile mode"), { target: { value: "scoped" } });

    fireEvent.click(q.getByRole("button", { name: "Grant admin" }));

    await waitFor(() => {
      expect(grantAdminRole).not.toHaveBeenCalled();
    });
  });
});
