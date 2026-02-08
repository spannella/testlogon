import { describe, expect, it, beforeEach, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ApiError } from "@/api/client";
import Register from "@/pages/Register";

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

const REGISTER_STORAGE_KEY = "register-pending";

const renderRegister = (initialEntries: string[] = ["/register"]) =>
  render(
    <MemoryRouter initialEntries={initialEntries}>
      <Register />
    </MemoryRouter>,
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
  it("shows password policy validation when missing letters or numbers", async () => {
    const user = userEvent.setup();
    renderRegister();

    await user.type(screen.getByLabelText(/full name/i), "Test User");
    await user.type(
      screen.getByLabelText(/email/i, { selector: "input[type='email']" }),
      "test@example.com",
    );
    await user.type(screen.getByLabelText(/^password/i), "passwordonly");
    await user.type(screen.getByLabelText(/confirm password/i), "passwordonly");
    await user.click(screen.getByRole("button", { name: /request access/i }));

    expect(
      await screen.findByText(/password must include letters and numbers/i),
    ).toBeInTheDocument();
  });

  it("shows password requirement checklist feedback", async () => {
    const user = userEvent.setup();
    renderRegister();

    await user.type(screen.getByLabelText(/^password/i), "Password1");
    await user.type(screen.getByLabelText(/confirm password/i), "Password1");

    expect(screen.getByText(/at least 8 characters/i)).toBeInTheDocument();
    expect(screen.getByText(/contains a letter/i)).toBeInTheDocument();
    expect(screen.getByText(/contains a number/i)).toBeInTheDocument();
    expect(screen.getByText(/passwords match/i)).toBeInTheDocument();
  });

  it("restores verification step from persisted registration", async () => {
    localStorage.setItem(
      REGISTER_STORAGE_KEY,
      JSON.stringify({ email: "persisted@example.com", enable_sms_mfa: false, enable_totp_mfa: false }),
    );

    renderRegister();

    expect(await screen.findByText(/verify your account/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/confirmation code/i)).toBeInTheDocument();
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

    const codeInput = await screen.findByLabelText(/confirmation code/i);
    expect(codeInput).toHaveValue("777888");
  });

  it("disables submit when email is already used", async () => {
    vi.useFakeTimers();
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    mocks.registerEmailCheck.mockResolvedValueOnce({ status: "ok", available: false });
    renderRegister();

    await user.type(
      screen.getByLabelText(/email/i, { selector: "input[type='email']" }),
      "taken@example.com",
    );
    vi.advanceTimersByTime(500);

    expect(await screen.findByText(/email is already in use/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /request access/i })).toBeDisabled();
    vi.useRealTimers();
  });

  it("shows rate limit message when email checks are throttled", async () => {
    vi.useFakeTimers();
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    mocks.registerEmailCheck.mockRejectedValueOnce(
      new ApiError(429, "Too many checks"),
    );
    renderRegister();

    await user.type(
      screen.getByLabelText(/email/i, { selector: "input[type='email']" }),
      "rate@example.com",
    );
    vi.advanceTimersByTime(500);

    expect(
      await screen.findByText(/too many checks\. please wait before trying again\./i),
    ).toBeInTheDocument();
    vi.useRealTimers();
  });
});
