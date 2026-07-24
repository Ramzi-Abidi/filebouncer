import type { Readable } from "node:stream";
import { crc32 } from "node:zlib";

import { describe, expect, it } from "vitest";
import { ZipFile } from "yazl";

import { FileSecurityEngine } from "../../src/engine/file-security-engine";

const S_IFLNK = 0o120000;

/** Minimal stored ZIP with an arbitrary entry name (yazl rejects unsafe paths). */
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

async function createZip(
  entries: { name: string; data?: Buffer; mode?: number; compress?: boolean }[],
): Promise<Buffer> {
  const zip = new ZipFile();

  for (const entry of entries) {
    zip.addBuffer(entry.data ?? Buffer.from("x"), entry.name, {
      mode: entry.mode,
      compress: entry.compress ?? true,
    });
  }

  zip.end();

  const chunks: Buffer[] = [];
  for await (const chunk of zip.outputStream as Readable) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array));
  }

  return Buffer.concat(chunks);
}

describe("archive scanner", () => {
  it("returns no threats for a normal zip", async () => {
    const engine = new FileSecurityEngine({ scanners: ["archive"] });
    const zip = await createZip([{ name: "hello.txt", data: Buffer.from("hello") }]);
    const result = await engine.scan(zip, { filename: "upload.zip" });

    expect(result.ok).toBe(true);
    expect(result.threats).toEqual([]);
    expect(result.scannersRun).toContain("archive");
  });

  it("flags ZIP slip path traversal", async () => {
    const engine = new FileSecurityEngine({ scanners: ["archive"] });
    const zip = createRawZip("../../etc/passwd");
    const result = await engine.scan(zip, { filename: "evil.zip" });

    expect(result.threats).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "ZIP_SLIP", scanner: "archive" })]),
    );
  });

  it("flags absolute entry paths", async () => {
    const engine = new FileSecurityEngine({ scanners: ["archive"] });
    const zip = createRawZip("/etc/passwd");
    const result = await engine.scan(zip, { filename: "evil.zip" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "ABSOLUTE_PATH", scanner: "archive" }),
      ]),
    );
  });

  it("flags too many entries as a zip bomb", async () => {
    const engine = new FileSecurityEngine({
      scanners: ["archive"],
      archive: { maxEntries: 3 },
    });
    const zip = await createZip([
      { name: "a.txt" },
      { name: "b.txt" },
      { name: "c.txt" },
      { name: "d.txt" },
    ]);
    const result = await engine.scan(zip, { filename: "bomb.zip" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "ZIP_BOMB_ENTRIES", scanner: "archive" }),
      ]),
    );
  });

  it("flags oversized uncompressed payloads", async () => {
    const engine = new FileSecurityEngine({
      scanners: ["archive"],
      archive: { maxTotalUncompressed: 100 },
    });
    const zip = await createZip([{ name: "big.txt", data: Buffer.alloc(200, 0x41) }]);
    const result = await engine.scan(zip, { filename: "bomb.zip" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "ZIP_BOMB_SIZE", scanner: "archive" }),
      ]),
    );
  });

  it("flags high compression ratios", async () => {
    const engine = new FileSecurityEngine({
      scanners: ["archive"],
      archive: { maxRatio: 5 },
    });
    const zip = await createZip([
      { name: "zeros.bin", data: Buffer.alloc(50_000, 0), compress: true },
    ]);
    const result = await engine.scan(zip, { filename: "bomb.zip" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "ZIP_BOMB_RATIO", scanner: "archive" }),
      ]),
    );
  });

  it("flags symlink entries by default", async () => {
    const engine = new FileSecurityEngine({ scanners: ["archive"] });
    const zip = await createZip([
      { name: "link", data: Buffer.from("/tmp/target"), mode: S_IFLNK | 0o777 },
    ]);
    const result = await engine.scan(zip, { filename: "link.zip" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "SYMLINK_ENTRY", scanner: "archive" }),
      ]),
    );
  });

  it("allows symlinks when configured", async () => {
    const engine = new FileSecurityEngine({
      scanners: ["archive"],
      archive: { allowSymlinks: true },
    });
    const zip = await createZip([
      { name: "link", data: Buffer.from("/tmp/target"), mode: S_IFLNK | 0o777 },
    ]);
    const result = await engine.scan(zip, { filename: "link.zip" });

    expect(result.threats.find((t) => t.code === "SYMLINK_ENTRY")).toBeUndefined();
  });

  it("flags corrupt archives", async () => {
    const engine = new FileSecurityEngine({ scanners: ["archive"] });
    const result = await engine.scan(Buffer.from("not-a-zip"), { filename: "broken.zip" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "CORRUPT_ARCHIVE", scanner: "archive" }),
      ]),
    );
  });

  it("skips non-archive files", async () => {
    const engine = new FileSecurityEngine({ scanners: ["archive"] });
    const result = await engine.scan(Buffer.from("hello"), {
      filename: "note.txt",
      declaredMime: "text/plain",
    });

    expect(result.scannersSkipped).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "archive", reason: "appliesTo returned false" }),
      ]),
    );
  });
});
