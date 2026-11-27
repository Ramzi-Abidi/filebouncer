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

function createMinimalPdf(): Buffer {
  const parts = ["%PDF-1.4\n"];
  const offsets: number[] = [];
  for (const object of [
    "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
    "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
    "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n",
  ]) {
    offsets.push(Buffer.byteLength(parts.join("")));
    parts.push(object);
  }

  const xrefOffset = Buffer.byteLength(parts.join(""));
  const entries = offsets
    .map((offset) => `${String(offset).padStart(10, "0")} 00000 n \n`)
    .join("");
  parts.push(
    `xref\n0 4\n0000000000 65535 f \n${entries}trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n${String(xrefOffset)}\n%%EOF\n`,
  );
  return Buffer.from(parts.join(""));
}

function createOpenXmlZip(mime: string): Buffer {
  const contentTypes = Buffer.from(
    `<Types><Override ContentType="${mime}.main+xml"/></Types>`,
    "utf8",
  );
  return createRawZip("[Content_Types].xml", contentTypes);
}

function createMimeZip(mime: string): Buffer {
  return createRawZip("mimetype", Buffer.from(mime, "utf8"));
}

const ZIP_CONTAINER_CASES = [
  {
    name: "DOCX",
    filename: "document.docx",
    detectedMime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    buffer: createOpenXmlZip(
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ),
  },
  {
    name: "XLSX",
    filename: "spreadsheet.xlsx",
    detectedMime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    buffer: createOpenXmlZip("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
  },
  {
    name: "PPTX",
    filename: "presentation.pptx",
    detectedMime: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    buffer: createOpenXmlZip(
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ),
  },
  {
    name: "EPUB",
    filename: "book.epub",
    detectedMime: "application/epub+zip",
    buffer: createMimeZip("application/epub+zip"),
  },
  {
    name: "OpenDocument",
    filename: "document.odt",
    detectedMime: "application/vnd.oasis.opendocument.text",
    buffer: createMimeZip("application/vnd.oasis.opendocument.text"),
  },
  {
    name: "APK",
    filename: "application.apk",
    detectedMime: "application/vnd.android.package-archive",
    buffer: createRawZip("classes.dex"),
  },
];

/** Tiny JPEG: SOI + APP0/JFIF stub + EOI. */
function createMinimalJpeg(): Buffer {
  return Buffer.from([
    0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x00, 0xff, 0xd9,
  ]);
}

/** Builds one JPEG segment: FF <marker> <2-byte big-endian length incl. itself> <payload>. */
function jpegSegment(marker: number, payload: Buffer): Buffer {
  const header = Buffer.from([0xff, marker, 0, 0]);
  header.writeUInt16BE(payload.length + 2, 2);
  return Buffer.concat([header, payload]);
}

/**
 * Camera-style JPEG: an EXIF (APP1) segment that embeds a complete thumbnail
 * JPEG (its own FFD8 ... FFD9), followed by a scan whose entropy-coded data
 * contains byte stuffing (FF 00) and a restart marker (FF D0), then the real EOI.
 */
function createCameraJpeg(): Buffer {
  const thumbnail = Buffer.concat([createMinimalJpeg(), Buffer.alloc(16, 0x11)]);
  const exif = jpegSegment(0xe1, Buffer.concat([Buffer.from("Exif\0\0"), thumbnail]));
  const quantTable = jpegSegment(0xdb, Buffer.alloc(65, 0x01));
  const startOfScan = jpegSegment(0xda, Buffer.alloc(10, 0x00));
  const entropyData = Buffer.concat([
    Buffer.alloc(200, 0x5a),
    Buffer.from([0xff, 0x00]), // stuffed 0xFF data byte
    Buffer.alloc(200, 0x3c),
    Buffer.from([0xff, 0xd0]), // restart marker inside scan data
    Buffer.alloc(200, 0x7e),
  ]);
  return Buffer.concat([
    Buffer.from([0xff, 0xd8]),
    exif,
    quantTable,
    startOfScan,
    entropyData,
    Buffer.from([0xff, 0xd9]),
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

  it("blocks a ZIP whose stored PDF header falls in the first 1024 bytes", async () => {
    const buffer = createRawZip("document.pdf", createMinimalPdf());
    const result = await new FileSecurityEngine().scan(buffer, { filename: "documents.zip" });

    expect(result.outcome).toBe("blocked");
    expect(result.ok).toBe(false);
    expect(result.errors).toEqual([]);
    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          scanner: "polyglot",
          code: "POLYGLOT_DETECTED",
          severity: "high",
        }),
      ]),
    );
    const finding = result.threats.find((threat) => threat.code === "POLYGLOT_DETECTED");
    expect(finding?.meta?.secondary).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ family: "pdf", offset: buffer.indexOf("%PDF-") }),
      ]),
    );
  });

  it("does not flag a ZIP that stores a PDF beyond the first 1024 bytes", async () => {
    const payload = Buffer.concat([Buffer.alloc(2048, 0x20), createMinimalPdf()]);
    const buffer = createRawZip("bundle/invoice.pdf", payload);
    const result = await new FileSecurityEngine().scan(buffer, { filename: "invoices.zip" });

    expect(buffer.indexOf("%PDF-")).toBeGreaterThan(1024);
    expect(result.threats).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it("still flags a PDF header deep inside a non-container file", async () => {
    const jpeg = createCameraJpeg();
    const buffer = Buffer.concat([jpeg, Buffer.alloc(2048, 0x20), createMinimalPdf()]);
    const engine = new FileSecurityEngine({ scanners: ["polyglot"] });
    const result = await engine.scan(buffer, { filename: "photo.jpg" });

    expect(buffer.indexOf("%PDF-")).toBeGreaterThan(1024);
    expect(result.threats.map((threat) => threat.code)).toEqual(["POLYGLOT_DETECTED"]);
  });

  it.each(ZIP_CONTAINER_CASES)(
    "does not flag a normal $name ZIP container",
    async ({ filename, detectedMime, buffer }) => {
      const engine = new FileSecurityEngine({ scanners: ["polyglot"] });
      const result = await engine.scan(buffer, { filename });

      expect(result.detectedMime).toBe(detectedMime);
      expect(result.threats).toEqual([]);
      expect(result.ok).toBe(true);
    },
  );

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
    expect(result.threats[0]?.meta?.secondary).toEqual(
      expect.arrayContaining([expect.objectContaining({ family: "zip", evidence: "zip-eocd" })]),
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

  it("does not flag a camera JPEG whose EXIF thumbnail has its own end marker", async () => {
    const engine = new FileSecurityEngine({ scanners: ["polyglot"] });
    const result = await engine.scan(createCameraJpeg(), { filename: "IMG_0001.jpg" });

    expect(result.detectedMime).toBe("image/jpeg");
    expect(result.threats).toEqual([]);
  });

  it("measures trailing content from the real end of a camera JPEG", async () => {
    const jpeg = createCameraJpeg();
    const buffer = Buffer.concat([jpeg, Buffer.alloc(64, 0x41)]);
    const engine = new FileSecurityEngine({ scanners: ["polyglot"] });
    const result = await engine.scan(buffer, { filename: "IMG_0001.jpg" });

    expect(result.threats.map((threat) => threat.code)).toEqual(["POLYGLOT_TRAILING_CONTENT"]);
    expect(result.threats[0]?.meta).toMatchObject({ endOffset: jpeg.length, trailingBytes: 64 });
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
      expect.arrayContaining([expect.objectContaining({ code: "POLYGLOT_DETECTED" })]),
    );
  });

  it("runs under scanners: all", async () => {
    const engine = new FileSecurityEngine({ scanners: "all" });
    const result = await engine.scan(createMinimalJpeg(), { filename: "photo.jpg" });

    expect(result.scannersRun).toContain("polyglot");
  });
});
