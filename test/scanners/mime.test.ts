import { describe, expect, it } from "vitest";

import { FileSecurityEngine } from "../../src/engine/file-security-engine";
import { MimeScanner } from "../../src/scanners/mime";
import type { ScannerContext } from "../../src/types";

/** 1×1 PNG — enough for file-type signature detection. */
const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
  "base64",
);

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
});
