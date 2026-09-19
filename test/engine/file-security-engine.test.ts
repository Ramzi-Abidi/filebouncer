import { describe, expect, it } from "vitest";

import {
  DEFAULT_MAX_FILE_SIZE,
  FileBouncerError,
  FileSecurityEngine,
  ScanFailureError,
  scanBuffer,
} from "../../src";
import type { Scanner, ScanOutcome, Severity, Threat } from "../../src";

const BUILT_IN_SCANNERS = ["mime", "metadata", "csv", "archive", "polyglot"];

const consideredScanners = (result: {
  scannersRun: string[];
  scannersSkipped: { name: string }[];
}) => [...result.scannersRun, ...result.scannersSkipped.map((s) => s.name)].sort();

const EMPTY = Buffer.alloc(0);
const PASS_OUTCOME: ScanOutcome = "pass";

const makeThreat = (index: number, severity: Severity = "low"): Threat => ({
  scanner: "many",
  code: `FINDING_${String(index)}`,
  severity,
  message: `finding ${String(index)}`,
});

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
    expect(result.outcome).toBe("incomplete");
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

  it("reports incomplete when a blocking finding and scanner error both occur", async () => {
    const blocking: Scanner = {
      name: "blocking",
      appliesTo: () => true,
      scan: async () => [makeThreat(0, "high")],
    };
    const failing: Scanner = {
      name: "failing",
      appliesTo: () => true,
      scan: async () => {
        throw new Error("failed");
      },
    };

    const result = await new FileSecurityEngine({
      scanners: [],
      customScanners: [blocking, failing],
    }).scan(EMPTY);

    expect(result.ok).toBe(false);
    expect(result.outcome).toBe("incomplete");
    expect(result.verdict).toBe("malicious");
  });

  it("maps ScanFailureError to the provided error code", async () => {
    const scannerFails: Scanner = {
      name: "fail closed",
      appliesTo: () => true,
      scan: async () => {
        throw new ScanFailureError("CORRUPT_INPUT", "cannot parse");
      },
    };

    const engine = new FileSecurityEngine({
      scanners: [],
      customScanners: [scannerFails],
    });
    const result = await engine.scan(EMPTY, { filename: "report.pdf" });

    expect(result.ok).toBe(false);
    expect(result.threats).toEqual([]);
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          scanner: "fail closed",
          code: "CORRUPT_INPUT",
          message: "cannot parse",
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
    expect(result.outcome).toBe("incomplete");
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
    expect(result.outcome).toBe(PASS_OUTCOME);
    expect(result.errors).toEqual([]);
    expect(result.timedOut).toBeFalsy();
    expect(result.findingsTruncated).toBeUndefined();
    expect(result.totalFindings).toBeUndefined();
  });

  it("rejects oversized input when maxFileSize is omitted (default 50 MiB)", async () => {
    const engine = new FileSecurityEngine({ scanners: [] });
    const result = await engine.scan(Buffer.alloc(DEFAULT_MAX_FILE_SIZE + 1), {
      filename: "huge.bin",
    });

    expect(result.ok).toBe(false);
    expect(result.outcome).toBe("blocked");
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

  it("retains at most 100 findings by default", async () => {
    const many: Scanner = {
      name: "many",
      appliesTo: () => true,
      scan: async () => Array.from({ length: 101 }, (_, index) => makeThreat(index)),
    };

    const result = await new FileSecurityEngine({
      scanners: [],
      customScanners: [many],
    }).scan(EMPTY);

    expect(result.threats).toHaveLength(100);
    expect(result.threats[0]?.code).toBe("FINDING_0");
    expect(result.threats[99]?.code).toBe("FINDING_99");
    expect(result.findingsTruncated).toBe(true);
    expect(result.totalFindings).toBe(101);
  });

  it("applies a custom findings limit across scanners in pipeline order", async () => {
    const first: Scanner = {
      name: "first",
      appliesTo: () => true,
      scan: async () => [makeThreat(0), makeThreat(1)],
    };
    const second: Scanner = {
      name: "second",
      appliesTo: () => true,
      scan: async () => [makeThreat(2), makeThreat(3)],
    };

    const result = await new FileSecurityEngine({
      scanners: [],
      maxFindings: 3,
      customScanners: [first, second],
    }).scan(EMPTY);

    expect(result.threats.map((threat) => threat.code)).toEqual([
      "FINDING_0",
      "FINDING_1",
      "FINDING_2",
    ]);
    expect(result.findingsTruncated).toBe(true);
    expect(result.totalFindings).toBe(4);
  });

  it("blocks and fails fast on a critical finding omitted by the limit", async () => {
    const mixed: Scanner = {
      name: "mixed",
      appliesTo: () => true,
      scan: async () => [makeThreat(0), makeThreat(1, "critical")],
    };
    const next: Scanner = {
      name: "next",
      appliesTo: () => true,
      scan: async () => [],
    };

    const result = await new FileSecurityEngine({
      scanners: [],
      maxFindings: 1,
      blockThreshold: "critical",
      failFast: true,
      customScanners: [mixed, next],
    }).scan(EMPTY);

    expect(result.threats).toEqual([makeThreat(0)]);
    expect(result.totalFindings).toBe(2);
    expect(result.findingsTruncated).toBe(true);
    expect(result.verdict).toBe("malicious");
    expect(result.ok).toBe(false);
    expect(result.scannersRun).toEqual(["mixed"]);
    expect(result.scannersSkipped).toEqual([
      expect.objectContaining({ name: "next", reason: "fail-fast" }),
    ]);
  });

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    "rejects invalid maxFindings value %s",
    (maxFindings) => {
      expect(() => new FileSecurityEngine({ maxFindings })).toThrowError(FileBouncerError);
    },
  );

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
    expect(mediumResult.outcome).toBe("pass");
    expect(mediumResult.verdict).toBe("suspicious");
    expect(mediumResult.threats).toEqual([
      expect.objectContaining({
        code: "MEDIUM_THREAT",
        severity: "medium",
      }),
    ]);

    expect(highResult.ok).toBe(false);
    expect(highResult.outcome).toBe("blocked");
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

  it("enables every built-in scanner when config is omitted", async () => {
    const result = await new FileSecurityEngine().scan(EMPTY, { filename: "report.pdf" });

    expect(consideredScanners(result)).toEqual([...BUILT_IN_SCANNERS].sort());
  });

  it("enables every built-in scanner from scanBuffer with no config", async () => {
    const result = await scanBuffer(EMPTY, { filename: "report.pdf" });

    expect(consideredScanners(result)).toEqual([...BUILT_IN_SCANNERS].sort());
  });

  it("still honors scanners: all", async () => {
    const result = await new FileSecurityEngine({ scanners: "all" }).scan(EMPTY, {
      filename: "report.pdf",
    });

    expect(consideredScanners(result)).toEqual([...BUILT_IN_SCANNERS].sort());
  });

  it("still honors an explicit scanner list", async () => {
    const result = await new FileSecurityEngine({ scanners: ["mime"] }).scan(EMPTY, {
      filename: "report.pdf",
    });

    expect(consideredScanners(result)).toEqual(["mime"]);
  });

  it("disables built-in scanners when scanners is an empty array", async () => {
    const result = await new FileSecurityEngine({ scanners: [] }).scan(EMPTY, {
      filename: "report.pdf",
    });

    expect(result.scannersRun).toEqual([]);
    expect(result.scannersSkipped).toEqual([]);
  });
});
