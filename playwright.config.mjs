import { defineConfig, devices } from '@playwright/test';

// Start `go run ./cmd/mockdata --reset` and `go run . --db-path mock-dashboard.db`
// before running this dev-only suite. Never point it at a production database.
export default defineConfig({
  testDir: './web/tests',
  timeout: 30_000,
  use: {
    baseURL: process.env.ICEVIRTUE_SMOKE_URL || 'http://127.0.0.1:8888',
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
});
