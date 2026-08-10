import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { crc32 } from "node:zlib";

import { describe, expect, it } from "vitest";

import { formatHelp, formatHuman, parseArgs, runCli } from "../src/cli";
import type { ScanResult } from "../src/types";

function createMinimalJpeg(): Buffer {
  return Buffer.from([
    0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x00, 0xff, 0xd9,
  ]);
}

function createRawZip(fileName: string, data: Buffer = Buffer.from("x")): Buffer {
  const name = Buffer.from(fileName, "utf8");
  const crc = crc32(data);

  const localHeader = Buffer.alloc(30);
  localHeader.writeUInt32LE(0x04034b50, 0);
  localHeader.writeUInt16LE(20, 4);
  localHeader.writeUInt16LE(0, 6);
  localHeader.writeUInt16LE(0, 8);
  localHeader.writeUInt16LE(0, 10);
  localHeader.writeUInt16LE(0, 12);
  localHeader.writeUInt32LE(crc, 14);
  localHeader.writeUInt32LE(data.length, 18);
  localHeader.writeUInt32LE(data.length, 22);
  localHeader.writeUInt16LE(name.length, 26);
  localHeader.writeUInt16LE(0, 28);

  const centralHeader = Buffer.alloc(46);
  centralHeader.writeUInt32LE(0x02014b50, 0);
  centralHeader.writeUInt16LE(20, 4);
  centralHeader.writeUInt16LE(20, 6);
  centralHeader.writeUInt16LE(0, 8);
  centralHeader.writeUInt16LE(0, 10);
  centralHeader.writeUInt16LE(0, 12);
  centralHeader.writeUInt16LE(0, 14);
  centralHeader.writeUInt32LE(crc, 16);
  centralHeader.writeUInt32LE(data.length, 20);
  centralHeader.writeUInt32LE(data.length, 24);
  centralHeader.writeUInt16LE(name.length, 28);
  centralHeader.writeUInt16LE(0, 30);
  centralHeader.writeUInt16LE(0, 32);
  centralHeader.writeUInt16LE(0, 34);
  centralHeader.writeUInt16LE(0, 36);
  centralHeader.writeUInt32LE(0, 38);
  centralHeader.writeUInt32LE(0, 42);

  const centralOffset = localHeader.length + name.length + data.length;
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(centralHeader.length + name.length, 12);
  end.writeUInt32LE(centralOffset, 16);
  end.writeUInt16LE(0, 20);

  return Buffer.concat([localHeader, name, data, centralHeader, name, end]);
}

describe("CLI helpers", () => {
  it("parses file path and --json", () => {
    expect(parseArgs(["photo.jpg", "--json"])).toEqual({
      file: "photo.jpg",
      json: true,
      help: false,
    });
  });

  it("rejects unknown flags", () => {
    expect(() => parseArgs(["--wat"])).toThrow(/Unknown option/);
  });

  it("formats human output for a blocked result", () => {
    const result = {
      ok: false,
      verdict: "malicious",
      size: 100,
      detectedMime: "image/jpeg",
      threats: [
        {
          scanner: "polyglot",
          code: "POLYGLOT_DETECTED",
          severity: "high",
          message: "multiple formats",
        },
      ],
      errors: [],
      scannersRun: ["polyglot"],
      scannersSkipped: [],
      durationMs: 1,
    } satisfies ScanResult;

    const text = formatHuman(result, "0.5.0", "polyglot.jpg");
    expect(text).toContain("filebouncer v0.5.0");
    expect(text).toContain("POLYGLOT_DETECTED");
    expect(text).toContain("Result: BLOCK");
  });

  it("includes usage text in help", () => {
    expect(formatHelp()).toContain("Usage: filebouncer");
  });
});

describe("runCli", () => {
  it("returns 3 when no file is provided", async () => {
    const logs: string[] = [];
    const code = await runCli([], {
      log: (msg) => logs.push(msg),
      error: (msg) => logs.push(msg),
    });
    expect(code).toBe(3);
    expect(logs.join("\n")).toContain("Usage: filebouncer");
  });

  it("returns 0 for a clean JPEG", async () => {
    const dir = await mkdtemp(join(tmpdir(), "fb-cli-"));
    const file = join(dir, "photo.jpg");
    await writeFile(file, createMinimalJpeg());

    const logs: string[] = [];
    const code = await runCli([file], {
      log: (msg) => logs.push(msg),
      error: (msg) => logs.push(msg),
    });

    expect(code).toBe(0);
    expect(logs.join("\n")).toContain("Result: OK");
  });

  it("returns 1 for a JPEG+ZIP polyglot", async () => {
    const dir = await mkdtemp(join(tmpdir(), "fb-cli-"));
    const file = join(dir, "polyglot.jpg");
    await writeFile(file, Buffer.concat([createMinimalJpeg(), createRawZip("a.txt")]));

    const logs: string[] = [];
    const code = await runCli([file], {
      log: (msg) => logs.push(msg),
      error: (msg) => logs.push(msg),
    });

    expect(code).toBe(1);
    expect(logs.join("\n")).toContain("POLYGLOT_DETECTED");
    expect(logs.join("\n")).toContain("Result: BLOCK");
  });

  it("returns 2 when the file does not exist", async () => {
    const code = await runCli(["/tmp/filebouncer-does-not-exist-xyz.jpg"], {
      log: () => undefined,
      error: () => undefined,
    });
    expect(code).toBe(2);
  });

  it("runs when invoked through a bin-style symlink to dist/cli.js", async () => {
    const cliJs = resolve("dist/cli.js");
    if (!existsSync(cliJs)) {
      return; // requires `pnpm build` first
    }

    const dir = await mkdtemp(join(tmpdir(), "fb-cli-bin-"));
    const file = join(dir, "polyglot.jpg");
    const bin = join(dir, "core");
    await writeFile(file, Buffer.concat([createMinimalJpeg(), createRawZip("a.txt")]));
    await symlink(cliJs, bin);

    // Invoke via node so argv[1] is still the symlink path (same as npm bin shims).
    const result = spawnSync(process.execPath, [bin, file], { encoding: "utf8" });
    expect(result.status).toBe(1);
    expect(result.stdout).toContain("POLYGLOT_DETECTED");
    expect(result.stdout).toContain("Result: BLOCK");
  });
});
