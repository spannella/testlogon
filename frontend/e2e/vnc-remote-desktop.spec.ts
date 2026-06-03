import { test, expect, type Page, type Route } from "@playwright/test";

const VNC_PATH = "/remote-desktop";

const BASE_SESSION = {
  session_id: "vnc_e2e_1",
  ws_url: "ws://localhost:6080/websockify",
  connect_params: { token: "token-abc" },
  created_at: Math.floor(Date.now() / 1000),
  expires_at: Math.floor(Date.now() / 1000) + 300,
  timeout_policy: {
    idle_timeout_seconds: 300,
    max_session_duration_seconds: 3600,
    warning_seconds: 60,
  },
};

type CapabilityMode = {
  targetId: string;
  capabilities: {
    clipboard: boolean;
    file_transfer: boolean;
    drag_drop_upload: boolean;
  };
  expectsUploadButton: boolean;
  // When file_transfer is false the component renders vnc-transfer-unsupported (no drag-drop zone).
  // When file_transfer is true the drag-drop zone is always rendered; drag_drop_upload controls its text.
  expectsTransferUnsupported: boolean;
  expectsDragDropDisabledText: boolean;
};

const CAPABILITY_MATRIX: CapabilityMode[] = [
  {
    targetId: "caps-none",
    capabilities: { clipboard: false, file_transfer: false, drag_drop_upload: false },
    expectsUploadButton: false,
    expectsTransferUnsupported: true,
    expectsDragDropDisabledText: false,
  },
  {
    targetId: "caps-upload-only",
    capabilities: { clipboard: true, file_transfer: true, drag_drop_upload: false },
    expectsUploadButton: true,
    expectsTransferUnsupported: false,
    expectsDragDropDisabledText: true,
  },
  {
    targetId: "caps-upload-dnd",
    capabilities: { clipboard: true, file_transfer: true, drag_drop_upload: true },
    expectsUploadButton: true,
    expectsTransferUnsupported: false,
    expectsDragDropDisabledText: false,
  },
];

async function setupAuthenticatedState(page: Page): Promise<void> {
  await page.addInitScript(() => {
    localStorage.setItem(
      "auth-store",
      JSON.stringify({
        state: {
          userId: "e2e-vnc-user",
          accessToken: "e2e-vnc-token",
          isAuthenticated: true,
        },
        version: 0,
      }),
    );

    class E2ERfb {
      target: Element;
      url: string;
      scaleViewport = false;
      viewOnly = false;
      handlers: Record<string, Array<(event: Event) => void>> = {};

      constructor(target: Element, url: string) {
        this.target = target;
        this.url = url;
        setTimeout(() => this.emit("connect"), 0);
      }

      addEventListener(event: string, handler: (event: Event) => void) {
        this.handlers[event] = this.handlers[event] ?? [];
        this.handlers[event]?.push(handler);
      }

      emit(event: string, detail?: unknown) {
        const evt = detail ? new CustomEvent(event, { detail }) : new Event(event);
        for (const handler of this.handlers[event] ?? []) {
          handler(evt);
        }
      }

      disconnect() {
        this.emit("disconnect");
      }

      sendCtrlAltDel() {}

      clipboardPasteFrom(_text: string) {}
    }

    (window as Window & { __TEST_RFB__?: unknown }).__TEST_RFB__ = E2ERfb;
  });
}

async function installApiMocks(page: Page): Promise<void> {
  // Register catch-all FIRST so it has LOWEST priority (Playwright: last registered wins).
  // Use the full localhost origin to avoid matching Vite module paths like /src/api/endpoints/vnc.ts
  // — those also contain "/api/" and would get JSON instead of JS, breaking the app bundle.
  await page.route("http://localhost:3000/api/**", async (route: Route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({}),
    });
  });

  // Broad /ui/** catch-all (lowest priority) so background AppShell calls
  // (e.g. /ui/theme, /ui/settings/preferences) never 401 and trigger the
  // logout-on-401 cascade that redirects to /login. Specific /ui mocks below
  // are registered later and therefore take priority.
  await page.route("http://localhost:3000/ui/**", async (route: Route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({}),
    });
  });

  await page.route("**/api/vnc/session", async (route: Route) => {
    const method = route.request().method();

    if (method === "POST") {
      const payload = (await route.request().postDataJSON()) as { target_id?: string };
      const targetId = String(payload?.target_id ?? "demo");
      if (targetId === "error-target") {
        await route.fulfill({
          status: 404,
          contentType: "application/json",
          body: JSON.stringify({
            detail: {
              error: {
                code: "VNC_TARGET_NOT_FOUND",
                message: "requested VNC target is not registered",
              },
            },
          }),
        });
        return;
      }

      const matrix = CAPABILITY_MATRIX.find((item) => item.targetId === targetId);
      const capabilities = matrix?.capabilities ?? {
        clipboard: true,
        file_transfer: false,
        drag_drop_upload: false,
      };

      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ...BASE_SESSION,
          session_id: `vnc_${targetId}`,
          capabilities,
        }),
      });
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        session_id: "vnc_any",
        status: "closed",
        closed_at: Math.floor(Date.now() / 1000),
      }),
    });
  });

  await page.route("**/api/vnc/session/*/transfer-fallback", async (route: Route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        session_id: "vnc_any",
        method: "object_upload_link",
        label: "Secure Upload Link",
        instructions: "Use secure upload link",
        url: "https://uploads.example.internal/vnc",
        expires_at: Math.floor(Date.now() / 1000) + 900,
      }),
    });
  });


  // Prevent AppShell 401 logout cascade: Header fires GET /ui/profile and GET /ui/alerts,
  // Sidebar fires GET /messaging/conversations, auth fires POST /ui/session/refresh.
  // Without these mocks, the fake localStorage token gets a 401 → refresh retry → logout → /login.
  await page.route("**/ui/profile**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ id: "e2e-vnc-user", email: "vnc@test.local", role: "user" }),
    }),
  );
  await page.route("**/ui/alerts**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ alerts: [], next_cursor: null, unread_count: 0 }),
    }),
  );
  await page.route("**/messaging/conversations**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ conversations: [], next_cursor: null }),
    }),
  );
  await page.route("**/ui/session/refresh**", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ok: true }) }),
  );
}

test.describe("VNC-016: remote desktop e2e", () => {
  test.beforeEach(async ({ page }) => {
    await setupAuthenticatedState(page);
    await installApiMocks(page);
    // Navigate in beforeEach so the lazy React chunk has time to load before each test.
    // The full E2E suite runs under load; give the "Target ID" label up to 15s to appear.
    await page.goto(VNC_PATH);
    await expect(page.getByLabel("Target ID")).toBeVisible({ timeout: 15000 });
  });

  test("connect/disconnect critical path and ADR error-code mapping", async ({ page }) => {

    await page.getByLabel("Target ID").fill("demo");
    await page.getByRole("button", { name: /connect viewer/i }).click();
    await expect(page.getByTestId("connection-state-badge")).toHaveText(/connected/i);

    await page.getByRole("button", { name: /^disconnect$/i }).click();
    await expect(page.getByTestId("connection-state-badge")).toHaveText(/disconnected/i);

    await page.getByLabel("Target ID").fill("error-target");
    await page.getByRole("button", { name: /connect viewer/i }).click();
    await expect(page.getByTestId("vnc-form-status")).toContainText("VNC_TARGET_NOT_FOUND");
  });

  test("clipboard supported vs unsupported behaviors", async ({ page }) => {

    await page.getByLabel("Target ID").fill("caps-upload-only");
    await page.getByRole("button", { name: /connect viewer/i }).click();
    await expect(page.getByTestId("connection-state-badge")).toHaveText(/connected/i);

    await page.getByTestId("vnc-clipboard-input").fill("hello clipboard");
    await page.getByRole("button", { name: /send to remote/i }).click();
    await expect(page.getByTestId("vnc-clipboard-status")).toContainText("sent to remote session");

    await page.getByRole("button", { name: /^disconnect$/i }).click();
    await expect(page.getByTestId("connection-state-badge")).toHaveText(/disconnected/i);

    await page.getByLabel("Target ID").fill("caps-none");
    await page.getByRole("button", { name: /connect viewer/i }).click();
    await expect(page.getByRole("button", { name: /read local clipboard/i })).toBeVisible();
    await page.getByRole("button", { name: /read local clipboard/i }).click();
    await expect(page.getByTestId("vnc-clipboard-status")).toContainText("disabled by server capability");
  });

  test("capability matrix gates upload/drag-drop controls", async ({ page }) => {

    for (const mode of CAPABILITY_MATRIX) {
      await page.getByRole("button", { name: /^disconnect$/i }).click().catch(() => {});

      await page.getByLabel("Target ID").fill(mode.targetId);
      await page.getByRole("button", { name: /connect viewer/i }).click();
      await expect(page.getByTestId("connection-state-badge")).toHaveText(/connected/i);

      const uploadBtn = page.getByRole("button", { name: /upload files/i });
      if (mode.expectsUploadButton) {
        await expect(uploadBtn).toBeVisible();
      } else {
        await expect(uploadBtn).toHaveCount(0);
      }

      if (mode.expectsTransferUnsupported) {
        // file_transfer: false — component renders transfer-unsupported, no drag-drop zone
        await expect(page.getByTestId("vnc-transfer-unsupported")).toBeVisible();
      } else {
        // file_transfer: true — drag-drop zone is always rendered; text depends on drag_drop_upload
        const dragDropZone = page.getByTestId("vnc-drag-drop-zone");
        if (mode.expectsDragDropDisabledText) {
          await expect(dragDropZone).toContainText("disabled for this session");
        } else {
          await expect(dragDropZone).toContainText("Drag and drop files here");
        }
      }
    }
  });
});
