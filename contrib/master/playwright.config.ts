import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "tests",
  testMatch: "*.spec.ts",
  workers: 1,
  use: {
    baseURL: "http://127.0.0.1:8791",
    viewport: { width: 1440, height: 960 },
    trace: "retain-on-failure",
  },
  webServer: {
    command: "node tests/browser-server.mjs",
    url: "http://127.0.0.1:8791",
    reuseExistingServer: false,
    timeout: 30000,
  },
});
