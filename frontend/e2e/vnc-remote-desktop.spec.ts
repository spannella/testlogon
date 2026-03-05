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
  expectsDragDropDisabledText: boolean;
};

const CAPABILITY_MATRIX: CapabilityMode[] = [
  {
    targetId: "caps-none",
    capabilities: { clipboard: false, file_transfer: false, drag_drop_upload: false },
    expectsUploadButton: false,
    expectsDragDropDisabledText: true,
  },
  {
    targetId: "caps-upload-only",
    capabilities: { clipboard: true, file_transfer: true, drag_drop_upload: false },
    expectsUploadButton: true,
    expectsDragDropDisabledText: true,
  },
  {
    targetId: "caps-upload-dnd",
    capabilities: { clipboard: true, file_transfer: true, drag_drop_upload: true },
    expectsUploadButton: true,
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

  await page.route("**/api/**", async (route: Route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({}),
    });
  });
}

test.describe("VNC-016: remote desktop e2e", () => {
  test.beforeEach(async ({ page }) => {
    await setupAuthenticatedState(page);
    await installApiMocks(page);
  });

  test("connect/disconnect critical path and ADR error-code mapping", async ({ page }) => {
    await page.goto(VNC_PATH);

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
    await page.goto(VNC_PATH);

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
    await page.goto(VNC_PATH);

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

      const dragDropZone = page.getByTestId("vnc-drag-drop-zone");
      if (mode.expectsDragDropDisabledText) {
        await expect(dragDropZone).toContainText("disabled for this session");
      } else {
        await expect(dragDropZone).toContainText("Drag and drop files here");
      }
    }
  });
});
