import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts", "packages/**/*.test.ts"],
    testTimeout: 300_000,
    hookTimeout: 300_000,
    pool: "forks",
    // snarkjs leaves worker threads alive; forks + teardown keeps vitest exiting cleanly
  },
});
