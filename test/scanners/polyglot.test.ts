import { crc32 } from "node:zlib";

import { describe, expect, it } from "vitest";

import { FileSecurityEngine } from "../../src/engine/file-security-engine";

/** Minimal stored ZIP with one entry. */
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

/** Tiny JPEG: SOI + APP0/JFIF stub + EOI. */
function createMinimalJpeg(): Buffer {
  return Buffer.from([
    0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0xff, 0xd9,
  ]);
}

/** Tiny PNG: signature + empty IHDR-sized header omitted; signature + IEND is enough for our scanner. */
function createMinimalPng(): Buffer {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(1, 0); // width
  ihdrData.writeUInt32BE(1, 4); // height
  ihdrData[8] = 8; // bit depth
  ihdrData[9] = 2; // color type RGB

  const ihdrType = Buffer.from("IHDR");
  const ihdrLen = Buffer.alloc(4);
  ihdrLen.writeUInt32BE(13, 0);
  const ihdrCrc = Buffer.alloc(4);
  ihdrCrc.writeUInt32BE(crc32(Buffer.concat([ihdrType, ihdrData])), 0);

  const iend = Buffer.from([
    0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
  ]);

  return Buffer.concat([signature, ihdrLen, ihdrType, ihdrData, ihdrCrc, iend]);
}

describe("polyglot scanner", () => {
  it("is registered when selected", async () => {
    const engine = new FileSecurityEngine({ scanners: ["polyglot"] });
    const result = await engine.scan(createMinimalJpeg(), { filename: "photo.jpg" });

    expect(result.scannersRun).toContain("polyglot");
    expect(result.ok).toBe(true);
    expect(result.threats).toEqual([]);
  });

  it("returns no threats for a normal JPEG", async () => {
    const engine = new FileSecurityEngine({ scanners: ["polyglot"] });
    const result = await engine.scan(createMinimalJpeg(), { filename: "photo.jpg" });

    expect(result.threats).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it("returns no threats for a normal ZIP", async () => {
    const engine = new FileSecurityEngine({ scanners: ["polyglot"] });
    const result = await engine.scan(createRawZip("a.txt"), { filename: "archive.zip" });

    expect(result.threats).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it("flags JPEG bytes followed by a ZIP archive", async () => {
    const polyglot = Buffer.concat([createMinimalJpeg(), createRawZip("hidden.txt")]);
    const engine = new FileSecurityEngine({ scanners: ["polyglot"] });
    const result = await engine.scan(polyglot, { filename: "photo.jpg" });

    expect(result.ok).toBe(false);
    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          scanner: "polyglot",
          code: "POLYGLOT_DETECTED",
          severity: "high",
        }),
      ]),
    );
    expect(result.threats[0]?.meta).toEqual(
      expect.objectContaining({
        secondary: expect.arrayContaining([
          expect.objectContaining({ family: "zip", evidence: "zip-eocd" }),
        ]),
      }),
    );
  });

  it("flags PNG bytes followed by a ZIP archive", async () => {
    const polyglot = Buffer.concat([createMinimalPng(), createRawZip("hidden.txt")]);
    const engine = new FileSecurityEngine({ scanners: ["polyglot"] });
    const result = await engine.scan(polyglot, { filename: "photo.png" });

    expect(result.ok).toBe(false);
    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "POLYGLOT_DETECTED", scanner: "polyglot" }),
      ]),
    );
  });

  it("flags unexplained trailing content after a JPEG end marker", async () => {
    const trailing = Buffer.alloc(64, 0x41);
    const buffer = Buffer.concat([createMinimalJpeg(), trailing]);
    const engine = new FileSecurityEngine({ scanners: ["polyglot"] });
    const result = await engine.scan(buffer, { filename: "photo.jpg" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "POLYGLOT_TRAILING_CONTENT",
          severity: "medium",
        }),
      ]),
    );
    // medium < default blockThreshold high
    expect(result.ok).toBe(true);
  });

  it("ignores tiny trailing padding within tolerance", async () => {
    const trailing = Buffer.alloc(8, 0x00);
    const buffer = Buffer.concat([createMinimalJpeg(), trailing]);
    const engine = new FileSecurityEngine({ scanners: ["polyglot"] });
    const result = await engine.scan(buffer, { filename: "photo.jpg" });

    expect(result.threats).toEqual([]);
  });

  it("flags a non-PDF primary that also contains a PDF header", async () => {
    const jpeg = createMinimalJpeg();
    // Insert PDF marker in the trailing region after EOI.
    const pdfTail = Buffer.from("%PDF-1.4\n%%EOF\n");
    const buffer = Buffer.concat([jpeg, pdfTail]);
    const engine = new FileSecurityEngine({ scanners: ["polyglot"] });
    const result = await engine.scan(buffer, { filename: "photo.jpg" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "POLYGLOT_DETECTED" }),
      ]),
    );
  });

  it("runs under scanners: all", async () => {
    const engine = new FileSecurityEngine({ scanners: "all" });
    const result = await engine.scan(createMinimalJpeg(), { filename: "photo.jpg" });

    expect(result.scannersRun).toContain("polyglot");
  });
});
