import { readFileSync, writeFileSync } from "node:fs";

import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    cli: "src/cli.ts",
  },
  format: ["esm"],
  target: "node20",
  platform: "node",
  outDir: "dist",
  dts: {
    entry: ["src/index.ts"],
  },
  sourcemap: true,
  clean: true,
  treeshake: true,
  splitting: false,
  minify: false,
  onSuccess() {
    const cliPath = "dist/cli.js";
    const content = readFileSync(cliPath, "utf8");
    if (!content.startsWith("#!")) {
      writeFileSync(cliPath, `#!/usr/bin/env node\n${content}`);
    }
  },
});
