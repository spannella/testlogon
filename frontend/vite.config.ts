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
      "/feed": "http://localhost:8000",
      "/posts": "http://localhost:8000",
      "/social": "http://localhost:8000",
      "/uploads": "http://localhost:8000",
      "/sse": "http://localhost:8000",
      "/notifications": "http://localhost:8000",
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
  },
});
