import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

// GAP-0323: dev-server parity for the production CrawlerMetaMiddleware.
// Social bots do not execute JS, so client-side react-helmet-async produces no
// OG/meta tags for them. For crawler User-Agents requesting public page routes
// we fetch the server-rendered meta HTML from the backend's /seo/meta-tags
// endpoint (the SAME source the prod middleware uses) and return it instead of
// the SPA shell. Normal dev requests are untouched. Mirrors the BOT_RE list +
// public-path list + backend source used in app/main.py (SECOPS-007 parity).
function crawlerMetaInjectPlugin(): Plugin {
  const BOT_RE =
    /facebookexternalhit|Twitterbot|LinkedInBot|Slackbot|Discordbot|WhatsApp|TelegramBot|Pinterest|Googlebot|bingbot|DuckDuckBot|Applebot|vkShare|W3C_Validator|ia_archiver|SemrushBot|AhrefsBot|MJ12bot|redditbot|Embedly|Google-InspectionTool/i;
  const PUBLIC_RE =
    /^\/(u\/[^/?#]+|posts\/[^/?#]+|event\/[^/?#]+\/[^/?#]+|videos\/[^/?#]+|live\/[^/?#]+)\/?$/;

  return {
    name: "crawler-meta-inject",
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        try {
          const method = (req.method ?? "GET").toUpperCase();
          const ua = req.headers["user-agent"] ?? "";
          const rawPath = (req.url ?? "/").split("?")[0];
          if (method !== "GET" || !BOT_RE.test(ua) || !PUBLIC_RE.test(rawPath)) {
            return next();
          }
          const backendResp = await fetch(
            `http://localhost:8000/seo/meta-tags?path=${encodeURIComponent(rawPath)}`,
          );
          const tags = await backendResp.text();
          const html = `<!DOCTYPE html>\n<html lang="en"><head>\n    ${tags}\n</head><body></body></html>\n`;
          res.setHeader("Content-Type", "text/html; charset=utf-8");
          res.statusCode = 200;
          res.end(html);
        } catch {
          // Any failure → fall through to the normal dev pipeline.
          next();
        }
      });
    },
  };
}

export default defineConfig({
  // The prod FastAPI serves the built SPA from the app/static StaticFiles
  // mount ("/static") and returns index.html at "/". Assets must therefore be
  // referenced under /static/ so they resolve when the shell is served from /.
  //
  // E2E HARNESS FIX: the Playwright suite (and the prod client router) navigate
  // to BARE app routes (http://localhost:3000/shop, /billing, /analytics, ...).
  // Under base "/static/" the dev server's baseMiddleware rejects those paths
  // with a plaintext 404 ("did you mean /static/shop"), and even if index.html
  // were served, <BrowserRouter basename={import.meta.env.BASE_URL}> would be
  // pinned to "/static/" and fail to match the bare path -> blank #root ->
  // ~410 specs fail with "heading not found". Setting E2E_BASE_ROOT=1 serves
  // the dev SPA at "/" (so BASE_URL==="/", router basename "/", assets under
  // "/"), which is exactly how prod/CI serve the shell (FastAPI returns
  // index.html at "/"). Prod BUILD + normal dev are untouched: without the env
  // var the base stays "/static/" so the built bundle still resolves under the
  // backend /static mount.
  base: process.env.E2E_BASE_ROOT === "1" ? "/" : "/static/",
  plugins: [crawlerMetaInjectPlugin(), react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
    dedupe: ["react", "react-dom"],
  },
  server: {
    host: "0.0.0.0",   // listen on all interfaces so the EC2 server is reachable
    port: 3000,
    strictPort: true,  // fail fast instead of silently falling back to 5173
    // Allow the app to be served behind a domain (e.g. via Caddy HTTPS). Leading
    // dot = match all subdomains. IPs/localhost are always allowed by Vite.
    allowedHosts: [".bitbazaar.cc", ".amazonaws.com"],
    hmr: process.env.VITE_PUBLIC_HMR_HOST
      ? {
          // Served behind an HTTPS reverse proxy (Caddy): the HMR WebSocket must
          // go to the public host over wss on 443 (Caddy proxies the upgrade).
          host: process.env.VITE_PUBLIC_HMR_HOST,
          protocol: "wss",
          clientPort: 443,
        }
      : {
          // Direct dev: open the WebSocket on the same port the page loaded from
          // (SSH tunnel localhost:3000 or EC2 IP :3000).
          clientPort: 3000,
        },
    proxy: {
      "/saml": "http://localhost:8000",
      "/ui": "http://localhost:8000",
      // SuiteCRM Knowledge Base router is mounted at /kb (auth) + /public/kb (public),
      // not under /ui or /api — proxy them so the KB frontend reaches the backend in dev.
      "/public/kb": "http://localhost:8000",
      "/kb": "http://localhost:8000",
      // OpenCATS public career portal router (mounted at /public/careers, outside /ui).
      "/public/careers": "http://localhost:8000",
      // OBP OAuth2/OIDC discovery + authorize/token/jwks (mounted at root, outside /ui).
      "/oauth": "http://localhost:8000",
      "/.well-known": "http://localhost:8000",
      // Browser SSH terminal WebSocket — needs ws:true for the upgrade to proxy.
      // Must precede the generic "/api" entry so the WS path matches here first.
      "/api/browser-ssh": { target: "http://localhost:8000", ws: true, changeOrigin: true },
      "/api": "http://localhost:8000",
      "/v1": "http://localhost:8000",
      "/messaging": "http://localhost:8000",
      // /messages is BOTH a SPA route (the messages page) and a backend API
      // prefix (call-recording endpoints live at /messages/recordings). Serve
      // index.html for browser navigations; proxy XHR/fetch to the backend.
      "/messages": {
        target: "http://localhost:8000",
        bypass: (req) => {
          const accept = req.headers["accept"] ?? "";
          if (typeof accept === "string" && accept.includes("text/html")) {
            return "/index.html";
          }
          return null;
        },
      },
      "/feed": {
        target: "http://localhost:8000",
        bypass: (req) => {
          // Browser page navigations to /feed → serve the SPA (index.html).
          // XHR/fetch API calls → proxy to backend.
          const accept = req.headers["accept"] ?? "";
          if (typeof accept === "string" && accept.includes("text/html")) {
            return "/index.html";
          }
          return null;
        },
      },
      // Scope to /r/ (affiliate short links GET /r/{code}); a bare "/r" prefix
      // also swallowed SPA routes like /remote-desktop and /remote/* and proxied
      // them to the backend (404), breaking direct navigation to those pages.
      "/r/": "http://localhost:8000",
      "/posts": "http://localhost:8000",
      "/social": "http://localhost:8000",
      "/uploads": "http://localhost:8000",
      "/sse": "http://localhost:8000",
      "/notifications": {
        target: "http://localhost:8000",
        bypass: (req) => {
          const accept = req.headers["accept"] ?? "";
          if (typeof accept === "string" && accept.includes("text/html")) {
            return "/index.html";
          }
          return null;
        },
      },
      "/mock": "http://localhost:8000",
      "/calendar/public": "http://localhost:8000",
      "/public/groups": "http://localhost:8000",
      "/public/fundraisers": "http://localhost:8000",
      "/public/files": "http://localhost:8000",
      "/seo": "http://localhost:8000",
      "/internal": "http://localhost:8000",
      "/tickets": {
        target: "http://localhost:8000",
        bypass: (req) => {
          // Let browser page navigations fall through to the SPA (index.html).
          // Only proxy JSON / XHR API calls to the backend.
          const accept = req.headers["accept"] ?? "";
          if (typeof accept === "string" && accept.includes("text/html")) {
            return "/index.html";
          }
          return null; // proxy to backend
        },
      },
      "/ticket-spaces": {
        target: "http://localhost:8000",
        bypass: (req) => {
          const accept = req.headers["accept"] ?? "";
          if (typeof accept === "string" && accept.includes("text/html")) {
            return "/index.html";
          }
          return null;
        },
      },
      // TKB-004: /boards mirrors the /tickets bypass — SPA route + API share the
      // prefix, so browser navigations get index.html and XHR/JSON proxy to backend.
      "/boards": {
        target: "http://localhost:8000",
        bypass: (req) => {
          const accept = req.headers["accept"] ?? "";
          if (typeof accept === "string" && accept.includes("text/html")) {
            return "/index.html";
          }
          return null;
        },
      },
      "/broadcast": {
        target: "http://localhost:8000",
        bypass: (req) => {
          const accept = req.headers["accept"] ?? "";
          if (typeof accept === "string" && accept.includes("text/html")) {
            return "/index.html";
          }
          return null;
        },
      },
      "/live": {
        target: "http://localhost:8000",
        bypass: (req) => {
          const accept = req.headers["accept"] ?? "";
          if (typeof accept === "string" && accept.includes("text/html")) {
            return "/index.html";
          }
          return null;
        },
      },
      "/questionnaires": {
        target: "http://localhost:8000",
        bypass: (req) => {
          const accept = req.headers["accept"] ?? "";
          if (typeof accept === "string" && accept.includes("text/html")) {
            return "/index.html";
          }
          return null;
        },
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: "./src/test/setup.ts",
    exclude: ["**/node_modules/**", "**/e2e/**"],
  },
});
