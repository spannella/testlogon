import { test, expect } from "@playwright/test";

// Skip when BROWSER_SSH_TERMINAL_ENABLED is not set (requires backend scaffold HTML page at /browser-ssh).
const SSH_ENABLED = process.env.BROWSER_SSH_TERMINAL_ENABLED === "1";

test.describe("browser SSH terminal", () => {

test("browser SSH e2e connect, run command, copy, paste, disconnect", async ({ page, context }) => {
  test.skip(!SSH_ENABLED, "BROWSER_SSH_TERMINAL_ENABLED is not set; backend HTML scaffold not available");
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: "http://127.0.0.1:8000" });

  await page.addInitScript(() => {
    (window as any).__BROWSER_SSH_TEST_HOOKS__ = {};
    (window as any).__browserSshWsMessages = [];
    (window as any).__clipboardReadText = "echo pasted\r\npwd\r\n";
    (window as any).__clipboardWrites = [];

    (window as any).navigator.clipboard = {
      readText: async () => (window as any).__clipboardReadText,
      writeText: async (value: string) => {
        (window as any).__clipboardWrites.push(value);
      },
    };

    class FakeFitAddon {
      fit() {}
    }

    class FakeTerminal {
      cols = 80;
      rows = 24;
      private buffer = "";
      private selected = "";
      private dataHandler: ((data: string) => void) | null = null;

      loadAddon(_addon: unknown) {}
      open(_el: Element) {}
      focus() {}
      onData(cb: (data: string) => void) { this.dataHandler = cb; }
      write(data: string) { this.buffer += data; }
      writeln(data: string) { this.buffer += `${data}\n`; }
      hasSelection() { return this.selected.length > 0; }
      getSelection() { return this.selected; }
      selectAll() { this.selected = this.buffer || "connected\n"; }
      clear() { this.buffer = ""; this.selected = ""; }
      reset() { this.buffer = ""; this.selected = ""; }
      dispose() {}
      // helper for future debugging
      __emitInput(data: string) { this.dataHandler?.(data); }
    }

    (window as any).FitAddon = { FitAddon: FakeFitAddon };
    (window as any).Terminal = FakeTerminal;

    class FakeWebSocket {
      static OPEN = 1;
      static CLOSED = 3;
      readyState = FakeWebSocket.OPEN;
      onopen: (() => void) | null = null;
      onclose: (() => void) | null = null;
      onerror: (() => void) | null = null;
      onmessage: ((ev: { data: string }) => void) | null = null;

      constructor(_url: string) {
        setTimeout(() => this.onopen?.(), 0);
      }

      send(payload: string) {
        const parsed = JSON.parse(payload);
        (window as any).__browserSshWsMessages.push(parsed);
        if (parsed.type === "connect") {
          this.onmessage?.({
            data: JSON.stringify({
              type: "status",
              payload: { phase: "connected", connected: true, message: "connected", cols: 80, rows: 24 },
            }),
          });
          return;
        }
        if (parsed.type === "input") {
          this.onmessage?.({
            data: JSON.stringify({ type: "output", payload: { data: parsed.payload.data } }),
          });
        }
      }

      close() {
        this.readyState = FakeWebSocket.CLOSED;
        this.onclose?.();
      }
    }

    (window as any).WebSocket = FakeWebSocket;
  });

  await page.route("**/api/browser-ssh/config", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        enabled: true,
        route: "/browser-ssh",
        ws_path: "/api/browser-ssh/ws",
        protocol_version: "v1",
        policy: {
          allowed_hosts_configured: false,
          denied_hosts_configured: false,
          allowed_ports_configured: false,
          denied_ports_configured: false,
        },
        limits: {
          idle_timeout_seconds: 900,
          max_session_duration_seconds: 3600,
          max_sessions_per_user: 2,
          connect_rate_limit_count: 10,
          connect_rate_limit_window_seconds: 60,
        },
      }),
    });
  });

  await page.goto(process.env.BROWSER_SSH_E2E_URL || "http://127.0.0.1:8000/browser-ssh");

  await page.fill("#browserSshHost", "fixture.internal");
  await page.fill("#browserSshPort", "22");
  await page.fill("#browserSshUsername", "alice");
  await page.fill("#browserSshPassword", "secret");
  await page.click("#browserSshConnectBtn");

  await expect(page.locator("#browserSshStateBadge")).toContainText("connected");

  await page.evaluate(() => {
    const wsMessages = (window as any).__browserSshWsMessages;
    wsMessages.length = 0;
  });

  await page.click("#browserSshPasteBtn");

  await expect
    .poll(async () => {
      return await page.evaluate(() => {
        const messages = (window as any).__browserSshWsMessages as Array<{ type: string; payload: { data?: string } }>;
        return messages.some((msg) => msg.type === "input" && msg.payload?.data === "echo pasted\npwd\n");
      });
    })
    .toBeTruthy();

  await page.evaluate(() => {
    const hooks = (window as any).__BROWSER_SSH_TEST_HOOKS__;
    hooks.terminal.selectAll();
  });
  await page.click("#browserSshCopyBtn");

  await expect
    .poll(async () => await page.evaluate(() => (window as any).__clipboardWrites.length))
    .toBeGreaterThan(0);

  await page.click("#browserSshDisconnectBtn");
  await expect(page.locator("#browserSshStateBadge")).toContainText("disconnected");
});

}); // end describe
