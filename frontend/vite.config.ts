import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": "http://localhost:8000" } },
  test: {
    environment: "jsdom",
    setupFiles: ["./tests/setup.ts"],
    // Playwright owns e2e/; Vitest runs component and hook tests only.
    include: ["tests/**/*.test.{ts,tsx}"],
  },
});
