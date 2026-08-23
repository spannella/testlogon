import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";

// This page is fed by the client-side algoStore (localStorage), not the network,
// but we still mock the api leaf to reject so a smoke mount never hits fetch.
vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client");
  return {
    ...actual,
    api: vi.fn(() => Promise.reject(new actual.ApiError(404, "Not found"))),
  };
});

import ActiveAlgosPage from "@/pages/algos/ActiveAlgosPage";

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <ActiveAlgosPage />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("ActiveAlgosPage render smoke (empty store)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.localStorage.clear();
  });

  it("mounts and shows its heading + client-side banner with no persisted algos", async () => {
    renderPage();
    expect(
      await screen.findByRole("heading", { level: 1, name: /Active Algos/i }),
    ).toBeInTheDocument();
    expect(screen.getByTestId("algo_client_side_banner")).toBeInTheDocument();
  });
});
