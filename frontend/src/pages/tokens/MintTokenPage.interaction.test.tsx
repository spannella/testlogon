import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

const mintToken = vi.fn();
const navigate = vi.fn();

vi.mock("@/api/endpoints/tokens", async () => {
  const actual = await vi.importActual<typeof import("@/api/endpoints/tokens")>("@/api/endpoints/tokens");
  return { ...actual, mintToken: (...a: unknown[]) => mintToken(...a) };
});

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigate };
});

vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));

import MintTokenPage from "./MintTokenPage";

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <MintTokenPage />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("MintTokenPage interaction", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("keeps the submit gated behind validation and shows the field errors", async () => {
    const user = userEvent.setup();
    renderPage();

    // Name is empty by default -> submit disabled + name error visible.
    const submit = screen.getByTestId("mint-submit");
    expect(submit).toBeDisabled();
    expect(screen.getByText("Name is required.")).toBeInTheDocument();

    // Fill a valid name but an invalid ticker -> still gated with ticker error.
    await user.type(screen.getByLabelText("Name"), "Jane Doe Revenue");
    await user.type(screen.getByLabelText("Ticker"), "!"); // fails 2-10 alnum
    expect(submit).toBeDisabled();
    expect(screen.getByText("Ticker must be 2-10 letters/numbers.")).toBeInTheDocument();
  });

  it("gates on a non-positive / out-of-range revenue-share %", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.type(screen.getByLabelText("Name"), "Jane Doe Revenue");
    await user.type(screen.getByLabelText("Ticker"), "JANE");

    const rev = screen.getByLabelText("Revenue-share %");
    await user.clear(rev);
    await user.type(rev, "0");
    expect(screen.getByText("Revenue-share % must be greater than 0.")).toBeInTheDocument();
    expect(screen.getByTestId("mint-submit")).toBeDisabled();

    await user.clear(rev);
    await user.type(rev, "150");
    expect(screen.getByText("Revenue-share % cannot exceed 100%.")).toBeInTheDocument();
    expect(screen.getByTestId("mint-submit")).toBeDisabled();
  });

  it("enables submit when all fields are valid and shows the $100 creation-fee confirm", async () => {
    const user = userEvent.setup();
    mintToken.mockResolvedValue({ token_id: "tk_1", ticker: "JANE" });
    renderPage();

    await user.type(screen.getByLabelText("Name"), "Jane Doe Revenue");
    await user.type(screen.getByLabelText("Ticker"), "JANE");
    // supply defaults to 1000000; revShare defaults to 2.5 -> all valid now.

    const submit = screen.getByTestId("mint-submit");
    await waitFor(() => expect(submit).toBeEnabled());
    await user.click(submit);

    // The money-safety confirm dialog appears with the $100.00 fee.
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("Confirm token mint")).toBeInTheDocument();
    expect(
      screen.getByText(/charges a one-time \$100\.00 creation fee/i),
    ).toBeInTheDocument();

    // Confirming triggers the mint mutation with the composed request.
    await user.click(screen.getByTestId("mint-confirm"));
    await waitFor(() => {
      expect(mintToken).toHaveBeenCalledWith(
        expect.objectContaining({ name: "Jane Doe Revenue", ticker: "JANE", total_supply: 1000000 }),
      );
    });
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/tokens/tk_1"));
  });
});
