import { describe, expect, it } from "vitest";

import { FileSecurityEngine } from "../../src/engine/file-security-engine";
import type { Scanner } from "../../src/types";

const EMPTY = Buffer.alloc(0);

describe("FileSecurityEngine", () => {
  it("sets ok false when a scanner throws, even with no threats", async () => {
    const scannerThrows: Scanner = {
      name: "throw error",
      appliesTo: () => true,
      scan: async () => {
        throw new Error("throw error");
      },
    };

    const engine = new FileSecurityEngine({
      scanners: [],
      customScanners: [scannerThrows],
    });
    const result = await engine.scan(EMPTY, { filename: "report.pdf" });

    expect(result.ok).toBe(false);
    expect(result.threats).toEqual([]);
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          scanner: "throw error",
          code: "SCANNER_ERROR",
          message: "throw error",
        }),
      ]),
    );
  });

  it("sets ok false when the scan times out", async () => {
    const slow: Scanner = {
      name: "slow",
      appliesTo: () => true,
      scan: async () => {
        await new Promise((resolve) => setTimeout(resolve, 30));
        return [];
      },
    };
    const next: Scanner = {
      name: "next",
      appliesTo: () => true,
      scan: async () => [],
    };

    const engine = new FileSecurityEngine({
      scanners: [],
      timeoutMs: 5,
      customScanners: [slow, next],
    });
    const result = await engine.scan(EMPTY, { filename: "report.pdf" });

    expect(result.ok).toBe(false);
    expect(result.timedOut).toBe(true);
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          scanner: "engine",
          code: "SCAN_TIMEOUT",
        }),
      ]),
    );
    expect(result.scannersSkipped).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "next", reason: "timeout" })]),
    );
  });

  it("keeps ok true for a clean scan", async () => {
    const clean: Scanner = {
      name: "clean",
      appliesTo: () => true,
      scan: async () => [],
    };

    const engine = new FileSecurityEngine({
      scanners: [],
      customScanners: [clean],
    });
    const result = await engine.scan(EMPTY, { filename: "report.pdf" });

    expect(result.ok).toBe(true);
    expect(result.errors).toEqual([]);
    expect(result.timedOut).toBeFalsy();
  });
});
