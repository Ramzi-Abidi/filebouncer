import { describe, expect, it } from "vitest";

import { FileSecurityEngine } from "../../src/engine/file-security-engine";

const EMPTY = Buffer.alloc(0);

describe("metadata scanner", () => {
  it("returns no threats for a normal filename", async () => {
    const engine = new FileSecurityEngine({ scanners: ["metadata"] });
    const result = await engine.scan(EMPTY, { filename: "report.pdf" });

    expect(result.ok).toBe(true);
    expect(result.threats).toEqual([]);
    expect(result.scannersRun).toContain("metadata");
  });

  it("flags double extensions", async () => {
    const engine = new FileSecurityEngine({ scanners: ["metadata"] });
    const result = await engine.scan(EMPTY, { filename: "invoice.pdf.exe" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "DOUBLE_EXTENSION", scanner: "metadata" }),
      ]),
    );
  });

  it("flags suspicious extensions", async () => {
    const engine = new FileSecurityEngine({ scanners: ["metadata"] });
    const result = await engine.scan(EMPTY, { filename: "malware.exe" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "SUSPICIOUS_EXTENSION", scanner: "metadata" }),
      ]),
    );
  });

  it("flags executables disguised as documents", async () => {
    const engine = new FileSecurityEngine({ scanners: ["metadata"] });
    const result = await engine.scan(EMPTY, { filename: "report.pdf.exe" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "EXECUTABLE_DISGUISED", scanner: "metadata" }),
      ]),
    );
  });

  it("flags unsafe path characters in filename", async () => {
    const engine = new FileSecurityEngine({ scanners: ["metadata"] });
    const result = await engine.scan(EMPTY, { filename: "../../etc/passwd" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "UNSAFE_FILENAME", scanner: "metadata" }),
      ]),
    );
  });

  it("flags null bytes in filename", async () => {
    const engine = new FileSecurityEngine({ scanners: ["metadata"] });
    const result = await engine.scan(EMPTY, { filename: "evil.pdf\u0000.jpg" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "NULL_BYTE_FILENAME", scanner: "metadata" }),
      ]),
    );
  });

  it("allows double extensions when configured", async () => {
    const engine = new FileSecurityEngine({
      scanners: ["metadata"],
      metadata: { allowDoubleExtension: true },
    });
    const result = await engine.scan(EMPTY, { filename: "archive.tar.gz" });

    expect(result.threats.find((t) => t.code === "DOUBLE_EXTENSION")).toBeUndefined();
  });

  it("skips when no filename is provided", async () => {
    const engine = new FileSecurityEngine({ scanners: ["metadata"] });
    const result = await engine.scan(EMPTY);

    expect(result.scannersSkipped).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "metadata", reason: "appliesTo returned false" }),
      ]),
    );
    expect(result.threats).toEqual([]);
  });
});
