import { describe, expect, it } from "vitest";

import { FileSecurityEngine } from "../../src/engine/file-security-engine";

const csv = (content: string) => Buffer.from(content, "utf8");

describe("csv scanner", () => {
  it("returns no threats for a normal CSV", async () => {
    const engine = new FileSecurityEngine({ scanners: ["csv"] });
    const result = await engine.scan(csv("name,amount\nAlice,100\nBob,200"), {
      filename: "export.csv",
    });

    expect(result.ok).toBe(true);
    expect(result.threats).toEqual([]);
    expect(result.scannersRun).toContain("csv");
  });

  it("flags cells starting with =", async () => {
    const engine = new FileSecurityEngine({ scanners: ["csv"] });
    const result = await engine.scan(csv("name,formula\nBob,=1+1"), {
      filename: "export.csv",
    });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "CSV_UNSAFE_CELL", scanner: "csv" }),
      ]),
    );
  });

  it("flags cells starting with +", async () => {
    const engine = new FileSecurityEngine({ scanners: ["csv"] });
    const result = await engine.scan(csv("value\n+cmd|'/c calc'!A0"), {
      filename: "export.csv",
    });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "CSV_UNSAFE_CELL", scanner: "csv" }),
      ]),
    );
  });

  it("does not flag negative numbers by default", async () => {
    const engine = new FileSecurityEngine({ scanners: ["csv"] });
    const result = await engine.scan(csv("name,amount\nAlice,-12.5\nBob,-100\nEve,-3"), {
      filename: "export.csv",
    });

    expect(result.ok).toBe(true);
    expect(result.threats).toEqual([]);
  });

  it("still flags - as unsafe when explicitly opted back into the prefix list", async () => {
    const engine = new FileSecurityEngine({
      scanners: ["csv"],
      csv: { prefixes: ["=", "+", "-", "@", "\t", "\r"] },
    });
    const result = await engine.scan(csv("name,amount\nAlice,-12.5"), {
      filename: "export.csv",
    });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "CSV_UNSAFE_CELL", scanner: "csv" }),
      ]),
    );
  });

  it("flags cells starting with @", async () => {
    const engine = new FileSecurityEngine({ scanners: ["csv"] });
    const result = await engine.scan(csv("value\n@SUM(1+1)"), { filename: "export.csv" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "CSV_UNSAFE_CELL", scanner: "csv" }),
      ]),
    );
  });

  it("flags formula cells after leading whitespace", async () => {
    const engine = new FileSecurityEngine({ scanners: ["csv"] });
    const result = await engine.scan(csv("value\n  =1+1"), { filename: "export.csv" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "CSV_UNSAFE_CELL", scanner: "csv" }),
      ]),
    );
  });

  it("respects maxRows", async () => {
    const engine = new FileSecurityEngine({
      scanners: ["csv"],
      csv: { maxRows: 2 },
    });
    const result = await engine.scan(csv("name,formula\nAlice,100\nBob,100\nEve,=1+1"), {
      filename: "export.csv",
    });

    expect(result.threats).toEqual([]);
  });

  it("uses a custom delimiter", async () => {
    const engine = new FileSecurityEngine({
      scanners: ["csv"],
      csv: { delimiter: ";" },
    });
    const result = await engine.scan(csv("name;formula\nBob;=1+1"), {
      filename: "export.csv",
    });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "CSV_UNSAFE_CELL", scanner: "csv" }),
      ]),
    );
  });

  it("skips non-CSV files", async () => {
    const engine = new FileSecurityEngine({ scanners: ["csv"] });
    const result = await engine.scan(Buffer.from("not csv at all"), {
      filename: "photo.jpg",
      declaredMime: "image/jpeg",
    });

    expect(result.scannersSkipped).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "csv", reason: "appliesTo returned false" }),
      ]),
    );
    expect(result.threats).toEqual([]);
  });

  it("runs when declared MIME is text/csv", async () => {
    const engine = new FileSecurityEngine({ scanners: ["csv"] });
    const result = await engine.scan(csv("value\n=1+1"), {
      declaredMime: "text/csv",
    });

    expect(result.scannersRun).toContain("csv");
    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "CSV_UNSAFE_CELL", scanner: "csv" }),
      ]),
    );
  });
});
