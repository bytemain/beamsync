import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  resolve: {
    alias: {
      "@beamsync/protocol": path.resolve(__dirname, "packages/protocol/src/index.ts"),
      "@beamsync/coordinator": path.resolve(__dirname, "packages/coordinator/src/index.ts"),
      "@beamsync/server": path.resolve(__dirname, "packages/server/src/index.ts"),
      "@beamsync/cli": path.resolve(__dirname, "packages/cli/src/index.ts"),
    },
  },
  test: {
    testTimeout: 30_000,
    hookTimeout: 15_000,
  },
});
