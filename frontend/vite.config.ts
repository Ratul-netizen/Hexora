import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dev server is bound to localhost only. Hexora holds a client's traffic and
// credentials, so nothing about it should be reachable from the network.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
