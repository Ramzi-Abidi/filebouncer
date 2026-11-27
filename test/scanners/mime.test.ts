import { describe, expect, it } from "vitest";

import { FileSecurityEngine } from "../../src/engine/file-security-engine";
import { MimeScanner } from "../../src/scanners/mime";
import type { ScannerContext } from "../../src/types";

/** 1×1 PNG — enough for file-type signature detection. */
const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
  "base64",
);

/**
 * Minimal Compound File Binary container (the format of legacy .doc/.xls/.ppt
 * and of .msi installers): 512-byte header + one directory sector whose root
 * entry carries `rootClsid`.
 */
function createCfb(rootClsid: Buffer = Buffer.alloc(16)): Buffer {
  const file = Buffer.alloc(1024);
  Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]).copy(file, 0);
  file.writeUInt16LE(0x003e, 0x18); // minor version
  file.writeUInt16LE(0x0003, 0x1a); // major version 3
  file.writeUInt16LE(0xfffe, 0x1c); // little-endian byte order
  file.writeUInt16LE(9, 0x1e); // 512-byte sectors
  file.writeUInt32LE(0, 0x30); // directory starts at sector 0 (file offset 512)
  Buffer.from("Root Entry", "utf16le").copy(file, 512);
  rootClsid.copy(file, 512 + 0x50);
  return file;
}

/** {000C1084-0000-0000-C000-000000000046} — Windows Installer package. */
const MSI_CLSID = Buffer.from([
  0x84, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
]);

const codes = (threats: { code: string }[]) => threats.map((threat) => threat.code);

describe("mime scanner", () => {
  it.each([
    ["jpeg", "jpg"],
    ["jpg", "jpeg"],
    ["tiff", "tif"],
    ["tif", "tiff"],
  ])(
    "accepts equivalent extensions %s and %s in default and strict modes",
    async (extension, detectedExt) => {
      const context = { extension, detectedExt } as ScannerContext;

      for (const config of [{}, { strict: true }]) {
        const threats = await new MimeScanner(config).scan(context);
        expect(threats).not.toEqual(
          expect.arrayContaining([expect.objectContaining({ code: "EXTENSION_MISMATCH" })]),
        );
      }
    },
  );

  it("returns no threats when extension and declared MIME match detected type", async () => {
    const engine = new FileSecurityEngine({ scanners: ["mime"] });
    const result = await engine.scan(PNG, {
      filename: "pixel.png",
      declaredMime: "image/png",
    });

    expect(result.ok).toBe(true);
    expect(result.threats).toEqual([]);
    expect(result.scannersRun).toContain("mime");
  });

  it("flags extension mismatch", async () => {
    const engine = new FileSecurityEngine({ scanners: ["mime"] });
    const result = await engine.scan(PNG, { filename: "photo.jpg" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "EXTENSION_MISMATCH", scanner: "mime" }),
      ]),
    );
  });

  it("flags declared MIME mismatch", async () => {
    const engine = new FileSecurityEngine({ scanners: ["mime"] });
    const result = await engine.scan(PNG, {
      filename: "pixel.png",
      declaredMime: "image/jpeg",
    });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "DECLARED_MIME_MISMATCH", scanner: "mime" }),
      ]),
    );
  });

  it("flags MIME not on allow list", async () => {
    const engine = new FileSecurityEngine({
      scanners: ["mime"],
      mime: { allowList: ["image/jpeg"] },
    });
    const result = await engine.scan(PNG, { filename: "pixel.png" });

    expect(result.threats).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "MIME_NOT_ALLOWED", scanner: "mime" }),
      ]),
    );
  });

  it("flags denied MIME types", async () => {
    const engine = new FileSecurityEngine({
      scanners: ["mime"],
      mime: { denyList: ["image/png"] },
    });
    const result = await engine.scan(PNG, { filename: "pixel.png" });

    expect(result.threats).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "MIME_DENIED", scanner: "mime" })]),
    );
  });

  it("uses critical severity for mismatches when strict is enabled", async () => {
    const engine = new FileSecurityEngine({
      scanners: ["mime"],
      mime: { strict: true },
    });
    const result = await engine.scan(PNG, { filename: "photo.jpg" });

    const mismatch = result.threats.find((t) => t.code === "EXTENSION_MISMATCH");
    expect(mismatch?.severity).toBe("critical");
  });

  it("skips when there is nothing to compare and no lists configured", async () => {
    const engine = new FileSecurityEngine({ scanners: ["mime"] });
    const result = await engine.scan(PNG);

    expect(result.scannersSkipped).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "mime", reason: "appliesTo returned false" }),
      ]),
    );
    expect(result.threats).toEqual([]);
  });
  describe("browser MIME aliases", () => {
    it.each([
      ["application/x-zip-compressed", "application/zip"],
      ["image/jpg", "image/jpeg"],
      ["image/pjpeg", "image/jpeg"],
      ["video/x-msvideo", "video/vnd.avi"],
      ["audio/x-wav", "audio/wav"],
    ])(
      "treats declared %s as matching detected %s, even in strict mode",
      async (declared, detected) => {
        const context = { declaredMime: declared, detectedMime: detected } as ScannerContext;
        const threats = await new MimeScanner({ strict: true }).scan(context);
        expect(threats).toEqual([]);
      },
    );

    it("does not treat a generic application/octet-stream declaration as a claim", async () => {
      const engine = new FileSecurityEngine({ scanners: ["mime"], mime: { strict: true } });
      const result = await engine.scan(PNG, {
        filename: "pixel.png",
        declaredMime: "application/octet-stream",
      });
      expect(result.threats).toEqual([]);
    });

    it("still flags a real declared MIME mismatch", async () => {
      const context = {
        declaredMime: "application/x-zip-compressed",
        detectedMime: "image/png",
      } as ScannerContext;
      const threats = await new MimeScanner().scan(context);
      expect(codes(threats)).toEqual(["DECLARED_MIME_MISMATCH"]);
    });

    it("matches allowList entries through aliases", async () => {
      const context = { detectedMime: "image/jpeg" } as ScannerContext;
      const threats = await new MimeScanner({ allowList: ["image/jpg"] }).scan(context);
      expect(threats).toEqual([]);
    });
  });

  describe("legacy Office (CFB) files", () => {
    it("accepts a .doc whose content is detected as a generic CFB container", async () => {
      const engine = new FileSecurityEngine({
        scanners: ["mime"],
        mime: { strict: true, allowList: ["application/msword"] },
      });
      const result = await engine.scan(createCfb(), {
        filename: "report.doc",
        declaredMime: "application/msword",
      });
      expect(result.detectedMime).toBe("application/x-cfb");
      expect(result.threats).toEqual([]);
    });

    it("identifies an MSI installer renamed to .doc and flags it", async () => {
      const engine = new FileSecurityEngine({
        scanners: ["mime"],
        mime: { allowList: ["application/msword"] },
      });
      const result = await engine.scan(createCfb(MSI_CLSID), {
        filename: "invoice.doc",
        declaredMime: "application/msword",
      });
      expect(result.detectedMime).toBe("application/x-msi");
      expect(codes(result.threats).sort()).toEqual([
        "DECLARED_MIME_MISMATCH",
        "EXTENSION_MISMATCH",
        "MIME_NOT_ALLOWED",
      ]);
    });
  });

  describe("text files on the allow list", () => {
    const allowCsv = () =>
      new FileSecurityEngine({ scanners: ["mime"], mime: { allowList: ["text/csv"] } });

    it.each([
      ["UTF-8", Buffer.from("name,city\nAnna,München\n", "utf8")],
      ["UTF-8 with BOM", Buffer.from("\uFEFFname,city\nAnna,Berlin\n", "utf8")],
      ["Windows-1252 (Excel on Windows)", Buffer.from("name,city\nRen\xe9,Paris\n", "latin1")],
      ["UTF-16LE with BOM", Buffer.from("\uFEFFname\tcity\r\nAnna\tBerlin\r\n", "utf16le")],
    ])("accepts a genuine %s CSV", async (_label, buffer) => {
      const result = await allowCsv().scan(buffer, {
        filename: "contacts.csv",
        declaredMime: "text/csv",
      });
      expect(result.threats).toEqual([]);
      expect(result.ok).toBe(true);
    });

    it.each([
      ["an HTML page", Buffer.from("<!DOCTYPE html><html><script>alert(1)</script></html>")],
      ["an SVG image", Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"></svg>')],
      ["a PHP script hidden after data", Buffer.from("a,b\n1,2\n<?php system($_GET['c']); ?>")],
      ["binary data", Buffer.from([0x00, 0x01, 0x02, 0x03, 0x61, 0x2c, 0x62])],
    ])("rejects %s named .csv", async (_label, buffer) => {
      const result = await allowCsv().scan(buffer, { filename: "data.csv" });
      expect(codes(result.threats)).toEqual(["MIME_NOT_ALLOWED"]);
      expect(result.ok).toBe(false);
    });

    it("does not let a text file satisfy a non-text allow list", async () => {
      const engine = new FileSecurityEngine({
        scanners: ["mime"],
        mime: { allowList: ["image/png"] },
      });
      const result = await engine.scan(Buffer.from("a,b\n1,2\n"), { filename: "data.csv" });
      expect(codes(result.threats)).toEqual(["MIME_NOT_ALLOWED"]);
    });
  });
});
