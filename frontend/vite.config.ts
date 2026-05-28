import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

export default defineConfig({
  plugins: [react(), tailwindcss()],
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
    hmr: {
      // Tell the HMR client to open its WebSocket on the same port the browser
      // used to load the page.  This works whether the user is on an SSH tunnel
      // (localhost:3000) or hitting the EC2 IP directly (18.222.237.167:3000).
      clientPort: 3000,
    },
    proxy: {
      "/ui": "http://localhost:8000",
      "/api": "http://localhost:8000",
      "/v1": "http://localhost:8000",
      "/messaging": "http://localhost:8000",
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
      "/posts": "http://localhost:8000",
      "/social": "http://localhost:8000",
      "/uploads": "http://localhost:8000",
      "/sse": "http://localhost:8000",
      "/notifications": "http://localhost:8000",
      "/mock": "http://localhost:8000",
      "/calendar/public": "http://localhost:8000",
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
