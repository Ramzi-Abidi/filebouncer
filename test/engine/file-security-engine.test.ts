import { describe, expect, it } from "vitest";

import { DEFAULT_MAX_FILE_SIZE, FileSecurityEngine } from "../../src/engine/file-security-engine";
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

  it("rejects oversized input when maxFileSize is omitted (default 50 MiB)", async () => {
    const engine = new FileSecurityEngine({ scanners: [] });
    const result = await engine.scan(Buffer.alloc(DEFAULT_MAX_FILE_SIZE + 1), {
      filename: "huge.bin",
    });

    expect(result.ok).toBe(false);
    expect(result.threats).toEqual([
      expect.objectContaining({
        scanner: "engine",
        code: "FILE_TOO_LARGE",
        severity: "critical",
      }),
    ]);
    expect(result.threats[0]?.message).toContain(String(DEFAULT_MAX_FILE_SIZE));
  });

  it("honors an explicit maxFileSize override", async () => {
    const engine = new FileSecurityEngine({
      scanners: [],
      maxFileSize: 100,
    });
    const blocked = await engine.scan(Buffer.alloc(101), { filename: "big.bin" });
    const allowed = await engine.scan(Buffer.alloc(100), { filename: "ok.bin" });

    expect(blocked.ok).toBe(false);
    expect(blocked.threats).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "FILE_TOO_LARGE" })]),
    );
    expect(allowed.ok).toBe(true);
    expect(allowed.threats).toEqual([]);
  });

  it("uses high as the default blockThreshold", async () => {
    const medium: Scanner = {
      name: "medium",
      appliesTo: () => true,
      scan: async () => [
        {
          scanner: "medium",
          code: "MEDIUM_THREAT",
          severity: "medium",
          message: "medium threat",
        },
      ],
    };

    const high: Scanner = {
      name: "high",
      appliesTo: () => true,
      scan: async () => [
        {
          scanner: "high",
          code: "HIGH_THREAT",
          severity: "high",
          message: "high threat",
        },
      ],
    };

    const mediumResult = await new FileSecurityEngine({
      scanners: [],
      customScanners: [medium],
    }).scan(EMPTY, { filename: "report.pdf" });

    const highResult = await new FileSecurityEngine({
      scanners: [],
      customScanners: [high],
    }).scan(EMPTY, { filename: "report.pdf" });

    expect(mediumResult.ok).toBe(true);
    expect(mediumResult.verdict).toBe("suspicious");
    expect(mediumResult.threats).toEqual([
      expect.objectContaining({
        code: "MEDIUM_THREAT",
        severity: "medium",
      }),
    ]);

    expect(highResult.ok).toBe(false);
    expect(highResult.verdict).toBe("malicious");
  });

  it("honors a custom blockThreshold", async () => {
    const medium: Scanner = {
      name: "medium",
      appliesTo: () => true,
      scan: async () => [
        {
          scanner: "medium",
          code: "MEDIUM_THREAT",
          severity: "medium",
          message: "medium threat",
        },
      ],
    };

    const result = await new FileSecurityEngine({
      scanners: [],
      blockThreshold: "medium",
      customScanners: [medium],
    }).scan(EMPTY, { filename: "report.pdf" });

    expect(result.ok).toBe(false);
  });

  it("skips later scanners on critical findings when failFast is enabled", async () => {
    const critical: Scanner = {
      name: "critical",
      appliesTo: () => true,
      scan: async () => [
        {
          scanner: "critical",
          code: "CRITICAL_THREAT",
          severity: "critical",
          message: "critical threat",
        },
      ],
    };

    const next: Scanner = {
      name: "next",
      appliesTo: () => true,
      scan: async () => [],
    };

    const result = await new FileSecurityEngine({
      scanners: [],
      failFast: true,
      customScanners: [critical, next],
    }).scan(EMPTY, { filename: "report.pdf" });

    expect(result.ok).toBe(false);
    expect(result.scannersRun).toEqual(["critical"]);
    expect(result.scannersSkipped).toEqual([
      expect.objectContaining({
        name: "next",
        reason: "fail-fast",
      }),
    ]);
  });

  it("continues after high findings when failFast is enabled", async () => {
    const high: Scanner = {
      name: "high",
      appliesTo: () => true,
      scan: async () => [
        {
          scanner: "high",
          code: "HIGH_THREAT",
          severity: "high",
          message: "high threat",
        },
      ],
    };

    const next: Scanner = {
      name: "next",
      appliesTo: () => true,
      scan: async () => [],
    };

    const result = await new FileSecurityEngine({
      scanners: [],
      failFast: true,
      customScanners: [high, next],
    }).scan(EMPTY, { filename: "report.pdf" });

    expect(result.ok).toBe(false);
    expect(result.scannersRun).toEqual(["high", "next"]);
    expect(result.scannersSkipped).toEqual([]);
  });
});
