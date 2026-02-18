import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import UsageBillingOverview from "../UsageBillingOverview";

const getUsageSummary = vi.fn();
const getUsageDaily = vi.fn();
const getUsageStorage = vi.fn();

vi.mock("@/api/endpoints/files", () => ({
  getUsageSummary: (...args: unknown[]) => getUsageSummary(...args),
  getUsageDaily: (...args: unknown[]) => getUsageDaily(...args),
  getUsageStorage: (...args: unknown[]) => getUsageStorage(...args),
}));

describe("UsageBillingOverview", () => {
  it("renders usage cards, trend, and overage", async () => {
    getUsageSummary.mockResolvedValue({
      period_id: "2026-02",
      upload: { used_bytes: 120, limit_bytes: 100, percent_used: 120 },
      download: { used_bytes: 80, limit_bytes: 100, percent_used: 80 },
      storage: { used_bytes: 200, limit_bytes: 100, percent_used: 200 },
      message_send: { used_count: 81, limit_count: 100, percent_used: 81 },
      post_publish: { used_count: 12, limit_count: 20, percent_used: 60 },
    });
    getUsageDaily.mockResolvedValue({
      from: "2026-02-01",
      to: "2026-02-28",
      items: [{ day_utc: "2026-02-01", upload_bytes_total: 5, download_bytes_total: 3, storage_bytes_end_of_day: 50 }],
    });
    getUsageStorage.mockResolvedValue({
      storage_bytes_current: 200,
      top_files: [{ path: "/big.bin", size: 150 }],
    });

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<MemoryRouter><QueryClientProvider client={qc}><UsageBillingOverview /></QueryClientProvider></MemoryRouter>);

    expect(await screen.findByText("Upload usage")).toBeInTheDocument();
    expect(screen.getByText("Messaging & Newsfeed usage")).toBeInTheDocument();
    expect(screen.getByText("Message sends")).toBeInTheDocument();
    expect(screen.getByText(/Near monthly limit/i)).toBeInTheDocument();
    expect(screen.getByText(/Estimated overage/i)).toBeInTheDocument();
    expect(screen.getByText(/Upload: 20 B over limit/i)).toBeInTheDocument();
    expect(screen.getByText("/big.bin")).toBeInTheDocument();
  });

  it("applies period input", async () => {
    getUsageSummary.mockResolvedValue({
      period_id: "2026-01",
      upload: { used_bytes: 1, limit_bytes: 100, percent_used: 1 },
      download: { used_bytes: 1, limit_bytes: 100, percent_used: 1 },
      storage: { used_bytes: 1, limit_bytes: 100, percent_used: 1 },
      message_send: { used_count: 1, limit_count: 100, percent_used: 1 },
      post_publish: { used_count: 1, limit_count: 100, percent_used: 1 },
    });
    getUsageDaily.mockResolvedValue({ from: "2026-01-01", to: "2026-01-31", items: [] });
    getUsageStorage.mockResolvedValue({ storage_bytes_current: 1, top_files: [] });

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<MemoryRouter><QueryClientProvider client={qc}><UsageBillingOverview /></QueryClientProvider></MemoryRouter>);

    const input = await screen.findByPlaceholderText("YYYY-MM");
    fireEvent.change(input, { target: { value: "2025-12" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));

    expect(getUsageSummary).toHaveBeenLastCalledWith("2025-12");
  });

  it("shows empty-state messaging when no daily items or overage", async () => {
    getUsageSummary.mockResolvedValue({
      period_id: "2026-03",
      upload: { used_bytes: 10, limit_bytes: 100, percent_used: 10 },
      download: { used_bytes: 20, limit_bytes: 100, percent_used: 20 },
      storage: { used_bytes: 30, limit_bytes: 100, percent_used: 30 },
      message_send: { used_count: 2, limit_count: 100, percent_used: 2 },
      post_publish: { used_count: 3, limit_count: 100, percent_used: 3 },
    });
    getUsageDaily.mockResolvedValue({ from: "2026-03-01", to: "2026-03-31", items: [] });
    getUsageStorage.mockResolvedValue({ storage_bytes_current: 30, top_files: [] });

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<MemoryRouter><QueryClientProvider client={qc}><UsageBillingOverview /></QueryClientProvider></MemoryRouter>);

    expect(await screen.findByText(/No daily usage events in this range./i)).toBeInTheDocument();
    expect(screen.getByText(/No overage currently estimated./i)).toBeInTheDocument();
  });

  it("renders chart legend and usage limit messaging", async () => {
    getUsageSummary.mockResolvedValue({
      period_id: "2026-04",
      upload: { used_bytes: 1024, limit_bytes: 2048, percent_used: 50 },
      download: { used_bytes: 512, limit_bytes: 1024, percent_used: 50 },
      storage: { used_bytes: 4096, limit_bytes: 8192, percent_used: 50 },
      message_send: { used_count: 95, limit_count: 100, percent_used: 95 },
      post_publish: { used_count: 10, limit_count: 100, percent_used: 10 },
    });
    getUsageDaily.mockResolvedValue({
      from: "2026-04-01",
      to: "2026-04-30",
      items: [{ day_utc: "2026-04-01", upload_bytes_total: 300, download_bytes_total: 100, storage_bytes_end_of_day: 0 }],
    });
    getUsageStorage.mockResolvedValue({ storage_bytes_current: 4096, top_files: [] });

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<MemoryRouter><QueryClientProvider client={qc}><UsageBillingOverview /></QueryClientProvider></MemoryRouter>);

    expect(await screen.findByText(/Blue = upload, Green = download/i)).toBeInTheDocument();
    expect(screen.getByText(/2.0 KB limit/i)).toBeInTheDocument();
    expect(screen.getAllByText(/50.0% used/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/Critical threshold reached/i)).toBeInTheDocument();
  });

  it("shows unit empty state when counters are missing", async () => {
    getUsageSummary.mockResolvedValue({
      period_id: "2026-05",
      upload: { used_bytes: 1, limit_bytes: 0, percent_used: 0 },
      download: { used_bytes: 1, limit_bytes: 0, percent_used: 0 },
      storage: { used_bytes: 1, limit_bytes: 0, percent_used: 0 },
    });
    getUsageDaily.mockResolvedValue({ from: "2026-05-01", to: "2026-05-31", items: [] });
    getUsageStorage.mockResolvedValue({ storage_bytes_current: 1, top_files: [] });

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<MemoryRouter><QueryClientProvider client={qc}><UsageBillingOverview /></QueryClientProvider></MemoryRouter>);

    expect(await screen.findByText(/No messaging\/newsfeed unit usage available for this period./i)).toBeInTheDocument();
  });

  it("shows summary error state", async () => {
    getUsageSummary.mockRejectedValue(new Error("boom"));
    getUsageDaily.mockResolvedValue({ from: "2026-05-01", to: "2026-05-31", items: [] });
    getUsageStorage.mockResolvedValue({ storage_bytes_current: 1, top_files: [] });

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<MemoryRouter><QueryClientProvider client={qc}><UsageBillingOverview /></QueryClientProvider></MemoryRouter>);

    expect(await screen.findByText(/Usage summary unavailable/i)).toBeInTheDocument();
    expect(screen.getByText(/Could not load messaging\/newsfeed usage./i)).toBeInTheDocument();
  });

});
