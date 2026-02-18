import { describe, expect, it, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import ProjectsPage from "./ProjectsPage";

const listProjects = vi.fn();
const createProject = vi.fn();

vi.mock("@/api/endpoints/projects", () => ({
  listProjects: (...args: unknown[]) => listProjects(...args),
  createProject: (...args: unknown[]) => createProject(...args),
}));

describe("ProjectsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const renderPage = () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return render(
      <MemoryRouter>
        <QueryClientProvider client={qc}>
          <ProjectsPage />
        </QueryClientProvider>
      </MemoryRouter>,
    );
  };

  it("renders projects list", async () => {
    listProjects.mockResolvedValue({
      items: [
        {
          id: "p1",
          owner: "user-1",
          name: "Alpha",
          description: "First project",
          tags: ["billing"],
          settings: {},
          created_at: "2026-01-01T00:00:00+00:00",
          updated_at: "2026-01-01T00:00:00+00:00",
        },
      ],
      cursor: null,
    });

    renderPage();

    expect(await screen.findByText("Alpha")).toBeInTheDocument();
    expect(screen.getByText("First project")).toBeInTheDocument();
  });

  it("creates project and refreshes list without reload", async () => {
    listProjects
      .mockResolvedValueOnce({ items: [], cursor: null })
      .mockResolvedValueOnce({
        items: [
          {
            id: "p2",
            owner: "user-1",
            name: "Beta",
            description: null,
            tags: ["ops"],
            settings: {},
            created_at: "2026-01-01T00:00:00+00:00",
            updated_at: "2026-01-01T00:00:00+00:00",
          },
        ],
        cursor: null,
      });
    createProject.mockResolvedValue({ id: "p2" });

    renderPage();

    expect(await screen.findByText("No projects yet")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /new project/i }));

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Beta" } });
    fireEvent.change(screen.getByLabelText("Tags (comma separated)"), { target: { value: "ops" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => {
      expect(createProject).toHaveBeenCalled();
      const firstCall = createProject.mock.calls[0];
      expect(firstCall).toBeDefined();
      expect(firstCall![0]).toEqual({
        name: "Beta",
        description: undefined,
        tags: ["ops"],
        settings: {},
      });
    });

    expect(await screen.findByText("Beta")).toBeInTheDocument();
    expect(listProjects).toHaveBeenCalledTimes(2);
  });

  it("shows validation message when name is missing", async () => {
    listProjects.mockResolvedValue({ items: [], cursor: null });
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: /new project/i }));
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    expect(await screen.findByText("Project name is required")).toBeInTheDocument();
    expect(createProject).not.toHaveBeenCalled();
  });
});
