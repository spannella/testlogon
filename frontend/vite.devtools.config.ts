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
    host: "0.0.0.0",
    port: 3001,
    strictPort: true,
    hmr: {
      clientPort: 3001,
    },
    proxy: {
      "/internal": "http://localhost:8000",
    },
  },
  build: {
    outDir: "dist-devtools",
    rollupOptions: {
      input: path.resolve(__dirname, "devtools.html"),
    },
  },
});
