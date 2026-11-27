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

  it("flags cells starting with @", async () => {
    const engine = new FileSecurityEngine({ scanners: ["csv"] });
    const result = await engine.scan(csv("value\n@SUM(1+1)"), { filename: "export.csv" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "CSV_UNSAFE_CELL", scanner: "csv" }),
      ]),
    );
  });

  it("allows negative numeric cells by default", async () => {
    const engine = new FileSecurityEngine({ scanners: ["csv"] });
    const result = await engine.scan(csv("value\n-1\n-1.5"), { filename: "export.csv" });

    expect(result.threats).toEqual([]);
  });

  it("allows callers to explicitly disallow negative cells", async () => {
    const engine = new FileSecurityEngine({
      scanners: ["csv"],
      csv: { prefixes: ["=", "+", "-", "@", "\t", "\r"] },
    });
    const result = await engine.scan(csv("value\n-1"), { filename: "export.csv" });

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
  it("does not flag phone numbers, negative numbers, placeholders or @handles", async () => {
    const engine = new FileSecurityEngine({ scanners: ["csv"] });
    const result = await engine.scan(
      csv(
        [
          "name,phone,balance,twitter,note",
          "Anna,+49 30 1234567,-12.50,@anna,-",
          'Bob,+1 (555) 123-4567,"-1,000.00",@bob_smith,+',
          "Cara,+44-20-7946-0958,-0.5,@cara.dev,- buy milk",
        ].join("\n"),
      ),
      { filename: "contacts.csv" },
    );

    expect(result.threats).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it.each([
    ["DDE payload behind a minus sign", "-2+3+cmd|' /C calc'!A0"],
    ["function call behind a plus sign", '+HYPERLINK("http://evil.example","click")'],
    ["sheet reference behind an @", "@Sheet1!A1"],
  ])("flags a %s", async (_label, cell) => {
    const engine = new FileSecurityEngine({ scanners: ["csv"] });
    const result = await engine.scan(csv(`value\n${cell}`), { filename: "export.csv" });

    expect(result.threats.map((threat) => threat.code)).toEqual(["CSV_UNSAFE_CELL"]);
  });
});
