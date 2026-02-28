import { describe, expect, it, beforeEach, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";

import { ApiError } from "@/api/client";
import Register from "@/pages/Register";
import { TooltipProvider } from "@/components/ui/tooltip";

const mocks = vi.hoisted(() => ({
  registerStart: vi.fn(),
  registerConfirm: vi.fn(),
  registerResend: vi.fn(),
  registerEmailCheck: vi.fn(),
  login: vi.fn(),
}));

vi.mock("@/api/endpoints/auth", () => ({
  registerStart: mocks.registerStart,
  registerConfirm: mocks.registerConfirm,
  registerResend: mocks.registerResend,
  registerEmailCheck: mocks.registerEmailCheck,
}));

vi.mock("@/stores/authStore", () => ({
  useAuthStore: () => ({
    login: mocks.login,
  }),
}));


vi.mock("@/components/ui/tooltip", () => ({
  TooltipProvider: ({ children }: { children: ReactNode }) => children,
  Tooltip: ({ children }: { children: ReactNode }) => children,
  TooltipTrigger: ({ children }: { children: ReactNode }) => children,
  TooltipContent: ({ children }: { children: ReactNode }) => children ?? null,
}));
const REGISTER_STORAGE_KEY = "register-pending";

const renderRegister = (initialEntries: string[] = ["/register"]) =>
  render(
    <TooltipProvider>
      <MemoryRouter initialEntries={initialEntries}>
        <Register />
      </MemoryRouter>
    </TooltipProvider>,
  );

beforeEach(() => {
  localStorage.clear();
  mocks.registerStart.mockReset();
  mocks.registerConfirm.mockReset();
  mocks.registerResend.mockReset();
  mocks.registerEmailCheck.mockReset();
  mocks.login.mockReset();
  mocks.registerEmailCheck.mockResolvedValue({ status: "ok", available: true });
});

describe("Register page", () => {

  it("toggles password visibility from the eye button", async () => {
    const user = userEvent.setup();
    renderRegister();

    const passwordInput = screen.getByLabelText(/^password/i);
    expect(passwordInput).toHaveAttribute("type", "password");

    await user.click(screen.getByRole("button", { name: /^show password$/i }));
    expect(passwordInput).toHaveAttribute("type", "text");

    await user.click(screen.getByRole("button", { name: /^hide password$/i }));
    expect(passwordInput).toHaveAttribute("type", "password");
  });

  it("toggles confirm-password visibility from the eye button", async () => {
    const user = userEvent.setup();
    renderRegister();

    const confirmInput = screen.getByLabelText(/confirm password/i, { selector: "input" });
    expect(confirmInput).toHaveAttribute("type", "password");

    await user.click(screen.getByRole("button", { name: /show confirm password/i }));
    expect(confirmInput).toHaveAttribute("type", "text");

    await user.click(screen.getByRole("button", { name: /hide confirm password/i }));
    expect(confirmInput).toHaveAttribute("type", "password");
  });

  it("enforces basic email conformance in UI", async () => {
    const user = userEvent.setup();
    renderRegister();

    await user.type(
      screen.getByLabelText(/email/i, { selector: "input[type='email']" }),
      "not-an-email",
    );

    expect(await screen.findByText(/enter a valid email/i)).toBeInTheDocument();
    expect(mocks.registerEmailCheck).not.toHaveBeenCalled();
  });

  it("normalizes basic email input before availability check", async () => {
    const user = userEvent.setup();
    renderRegister();

    await user.type(
      screen.getByLabelText(/email/i, { selector: "input[type='email']" }),
      " user@example.com ",
    );

    await waitFor(() => {
      expect(mocks.registerEmailCheck).toHaveBeenCalledWith({ email: "user@example.com" });
    });
  });
  it("shows password policy validation when too short", async () => {
    const user = userEvent.setup();
    renderRegister();

    await user.type(screen.getByLabelText(/full name/i), "Test User");
    await user.type(
      screen.getByLabelText(/email/i, { selector: "input[type='email']" }),
      "test@example.com",
    );
    await user.type(screen.getByLabelText(/^password/i), "short123");
    await user.type(screen.getByLabelText(/confirm password/i, { selector: "input" }), "short123");
    await user.click(screen.getByRole("button", { name: /request access/i }));

    expect(
      await screen.findByText(/password must be at least 12 characters/i),
    ).toBeInTheDocument();
  });


  it("shows password strength meter progression", async () => {
    const user = userEvent.setup();
    renderRegister();

    expect(screen.getByText(/password strength/i)).toBeInTheDocument();
    expect(screen.getByText(/^very weak$/i)).toBeInTheDocument();

    await user.type(screen.getByLabelText(/^password/i), "short");
    expect(screen.getByText(/^very weak$/i)).toBeInTheDocument();

    await user.clear(screen.getByLabelText(/^password/i));
    await user.type(screen.getByLabelText(/^password/i), "StrongPassphrase42!");
    expect(screen.getByText(/^strong$/i)).toBeInTheDocument();
  });

  it("shows password requirement checklist feedback", async () => {
    const user = userEvent.setup();
    renderRegister();

    await user.type(screen.getByLabelText(/^password/i), "StrongPassphrase42!");
    await user.type(screen.getByLabelText(/confirm password/i, { selector: "input" }), "StrongPassphrase42!");

    expect(screen.getByText(/at least 12 characters/i)).toBeInTheDocument();
    expect(screen.getByText(/no more than 128 characters/i)).toBeInTheDocument();
    expect(screen.getByText(/one special character/i)).toBeInTheDocument();
    expect(screen.getByText(/passwords match/i)).toBeInTheDocument();
  });

  it("restores verification step from persisted registration", async () => {
    localStorage.setItem(
      REGISTER_STORAGE_KEY,
      JSON.stringify({ email: "persisted@example.com", enable_sms_mfa: false, enable_totp_mfa: false }),
    );

    renderRegister();

    expect(await screen.findByText(/verify your account/i)).toBeInTheDocument();
    expect(screen.getAllByText(/confirmation code/i).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /resend code/i })).toBeInTheDocument();
  });

  it("shows rate limit message when resend fails", async () => {
    const user = userEvent.setup();
    localStorage.setItem(
      REGISTER_STORAGE_KEY,
      JSON.stringify({ email: "resend@example.com", enable_sms_mfa: false, enable_totp_mfa: false }),
    );
    mocks.registerResend.mockRejectedValueOnce(
      new ApiError(429, "Too many verification emails; try again later"),
    );

    renderRegister();

    await user.click(await screen.findByRole("button", { name: /resend code/i }));

    await waitFor(() => {
      expect(mocks.registerResend).toHaveBeenCalledWith({
        email: "resend@example.com",
        delivery_method: "email",
        phone: undefined,
        enable_sms_mfa: false,
        enable_totp_mfa: false,
      });
    });

    expect(
      await screen.findByText(/too many verification emails; try again later/i),
    ).toBeInTheDocument();
  });

  it("prefills verification code from URL params", async () => {
    renderRegister(["/register?email=param@example.com&code=777888"]);

    // Wait for the verify step to appear (multiple elements contain "confirmation code")
    await screen.findAllByText(/confirmation code/i);
    // OtpInput renders 6 individual digit inputs; verify the combined value
    const digitInputs = screen.getAllByRole("textbox");
    const combined = digitInputs.map((el) => (el as HTMLInputElement).value).join("");
    expect(combined).toBe("777888");
  });

  it("shows email availability result after check", async () => {
    const user = userEvent.setup();
    mocks.registerEmailCheck.mockResolvedValueOnce({ status: "ok", available: true });
    renderRegister();

    await user.type(
      screen.getByLabelText(/email/i, { selector: "input[type='email']" }),
      "free@example.com",
    );

    expect(await screen.findByText(/email looks valid/i)).toBeInTheDocument();
  });

  it("shows rate limit message when email checks are throttled", async () => {
    const user = userEvent.setup();
    mocks.registerEmailCheck.mockRejectedValueOnce(
      new ApiError(429, "Too many checks"),
    );
    renderRegister();

    await user.type(
      screen.getByLabelText(/email/i, { selector: "input[type='email']" }),
      "rate@example.com",
    );

    expect(
      await screen.findByText(/too many checks\. please wait before trying again\./i),
    ).toBeInTheDocument();
  });

  it("recovers when email check never resolves", async () => {
    vi.useFakeTimers();
    try {
      mocks.registerEmailCheck.mockImplementationOnce(() => new Promise(() => {}));
      renderRegister();

      fireEvent.change(screen.getByLabelText(/email/i, { selector: "input[type='email']" }), {
        target: { value: "stuck@example.com" },
      });

      await act(async () => {
        vi.advanceTimersByTime(400);
      });
      expect(screen.getByText(/checking email availability/i)).toBeInTheDocument();

      await act(async () => {
        vi.advanceTimersByTime(8000);
      });
      expect(screen.getByText(/unable to check email availability\. please try again\./i)).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });
});
