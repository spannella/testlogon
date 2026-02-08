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
    port: 3000,
    proxy: {
      "/ui": "http://localhost:8000",
      "/api": "http://localhost:8000",
      "/v1": "http://localhost:8000",
      "/messaging": "http://localhost:8000",
      "/feed": "http://localhost:8000",
      "/posts": "http://localhost:8000",
      "/social": "http://localhost:8000",
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
