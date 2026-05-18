import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

// Rewrites / and /index.html to /devtools.html so the dev server serves the
// correct entry point (Vite always falls back to index.html by default).
function devtoolsEntryPlugin(): Plugin {
  return {
    name: "devtools-entry",
    configureServer(server) {
      server.middlewares.use((req, _res, next) => {
        if (req.url === "/" || req.url === "/index.html") {
          req.url = "/devtools.html";
        }
        next();
      });
    },
  };
}

export default defineConfig({
  plugins: [devtoolsEntryPlugin(), react(), tailwindcss()],
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
  cacheDir: "node_modules/.vite-devtools",
  build: {
    outDir: "dist-devtools",
    rollupOptions: {
      input: path.resolve(__dirname, "devtools.html"),
    },
  },
});
