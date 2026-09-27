import { defineConfig, devices } from "@playwright/test";

// End-to-end tests drive the real API serving the built UI from one origin,
// over a freshly seeded synthetic demo workspace. Build first: `npm run build`.
// HESTIA_E2E_CHANNEL=chrome uses an installed Google Chrome instead of
// Playwright's bundled Chromium (`npx playwright install chromium`).
// HESTIA_E2E_BASE_URL targets an already running demo workspace (for example the
// Docker container after `hestia demo-seed`) instead of starting one.
const port = Number(process.env.HESTIA_E2E_PORT ?? 8765);
const external = process.env.HESTIA_E2E_BASE_URL;
const channel = process.env.HESTIA_E2E_CHANNEL || undefined;

export default defineConfig({
  testDir: "./e2e",
  outputDir: "./test-results/e2e",
  // One server, one demo workspace and one active run at a time: run serially.
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: external ?? `http://127.0.0.1:${port}`,
    channel,
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "desktop",
      use: {
        ...devices["Desktop Chrome"],
        channel,
        viewport: { width: 1366, height: 900 },
      },
    },
    {
      name: "mobile-390",
      use: {
        ...devices["Desktop Chrome"],
        channel,
        viewport: { width: 390, height: 844 },
        isMobile: true,
        hasTouch: true,
        deviceScaleFactor: 2,
      },
    },
  ],
  webServer: external
    ? undefined
    : {
        command: `uv run --project .. python ../scripts/demo_server.py --fresh --artifact-root test-results/e2e-workspace --port ${port} --pace 0.6`,
        url: `http://127.0.0.1:${port}/api/health`,
        reuseExistingServer: false,
        timeout: 120_000,
        env: { HESTIA_FRONTEND_DIST: "dist", HESTIA_DATA_ROOT: "../data" },
      },
});
