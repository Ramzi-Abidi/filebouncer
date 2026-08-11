import { realpathSync } from "node:fs";
import { stat } from "node:fs/promises";
import { createRequire } from "node:module";
import { basename, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { FileSecurityEngine } from "./engine/file-security-engine";
import type { ScanResult } from "./types";

export interface CliOptions {
  file?: string;
  json: boolean;
  help: boolean;
}

export const parseArgs = (argv: string[]): CliOptions => {
  const opts: CliOptions = { json: false, help: false };

  for (const arg of argv) {
    if (arg === "--help" || arg === "-h") {
      opts.help = true;
      continue;
    }
    if (arg === "--json") {
      opts.json = true;
      continue;
    }
    if (arg.startsWith("-")) {
      throw new Error(`Unknown option: ${arg}`);
    }
    if (opts.file) {
      throw new Error("Only one file path is supported");
    }
    opts.file = arg;
  }

  return opts;
};

export const formatHelp = (): string =>
  [
    "Usage: filebouncer <path> [--json]",
    "",
    "Scan a file with @filebouncer/core (MIME, metadata, CSV, archive, polyglot).",
    "",
    "Options:",
    "  --json    Print the raw ScanResult as JSON",
    "  -h, --help  Show this help",
    "",
    "Exit codes:",
    "  0  ok (no blocking findings / scan failures)",
    "  1  blocked or scan incomplete (result.ok === false)",
    "  2  unexpected error (e.g. file not found)",
    "  3  usage error",
  ].join("\n");

export const formatHuman = (result: ScanResult, version: string, fileLabel: string): string => {
  const lines: string[] = [
    `filebouncer v${version}`,
    "",
    `File: ${fileLabel}`,
    `Size: ${String(result.size)} bytes`,
  ];

  if (result.detectedMime) {
    lines.push(`Detected MIME: ${result.detectedMime}`);
  } else {
    lines.push("Detected MIME: (unknown)");
  }

  if (result.threats.length > 0) {
    lines.push("", "Findings:");
    for (const threat of result.threats) {
      lines.push(`  ${threat.severity.padEnd(8)} ${threat.code}`);
      lines.push(`           ${threat.message}`);
    }
  } else {
    lines.push("", "Findings: (none)");
  }

  if (result.errors.length > 0) {
    lines.push("", "Errors:");
    for (const err of result.errors) {
      lines.push(`  ${err.code}  ${err.message}`);
    }
  }

  lines.push("");
  if (result.ok) {
    lines.push("Result: OK");
  } else {
    lines.push("Result: BLOCK");
  }

  return lines.join("\n");
};

const readVersion = (): string => {
  try {
    const require = createRequire(import.meta.url);
    const pkg = require("../package.json") as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
};

export const runCli = async (
  argv: string[],
  io: {
    log: (msg: string) => void;
    error: (msg: string) => void;
  } = {
    log: (msg) => console.log(msg),
    error: (msg) => console.error(msg),
  },
): Promise<number> => {
  let opts: CliOptions;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    io.error(err instanceof Error ? err.message : "Invalid arguments");
    io.error(formatHelp());
    return 3;
  }

  if (opts.help || !opts.file) {
    io.log(formatHelp());
    return opts.help ? 0 : 3;
  }

  const filePath = resolve(opts.file);
  let stats;
  try {
    // stat, not lstat: follows a symlink so a symlink-to-directory is caught
    // by the isFile() check below rather than reported as "found".
    stats = await stat(filePath);
  } catch {
    io.error(`File not found: ${filePath}`);
    return 2;
  }
  if (!stats.isFile()) {
    io.error(`Not a file: ${filePath}`);
    return 2;
  }

  const engine = new FileSecurityEngine({ scanners: "all" });
  const result = await engine.scan({ path: filePath }, { filename: basename(filePath) });

  if (opts.json) {
    io.log(JSON.stringify(result, null, 2));
  } else {
    io.log(formatHuman(result, readVersion(), basename(filePath)));
  }

  return result.ok ? 0 : 1;
};

const isMain = (): boolean => {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    // Bin shims are symlinks (e.g. node_modules/.bin/core → dist/cli.js).
    // Compare against the real path so npx / pnpm exec actually run the CLI.
    return import.meta.url === pathToFileURL(realpathSync(resolve(entry))).href;
  } catch {
    return false;
  }
};

if (isMain()) {
  const code = await runCli(process.argv.slice(2));
  process.exit(code);
}
