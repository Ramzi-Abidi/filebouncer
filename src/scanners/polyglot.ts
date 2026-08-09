import type { PolyglotConfig, Scanner, ScannerContext, Severity, Threat } from "../types";

const DEFAULT_TRAILING_TOLERANCE = 32;
/** EOCD is within this many bytes of the end (22-byte record + max comment). */
const ZIP_EOCD_WINDOW = 22 + 65_535;

const ZIP_FAMILIES = new Set(["zip"]);

interface FormatHit {
  family: string;
  mime: string;
  offset: number;
  evidence: string;
}

interface ResolvedPolyglotConfig {
  minSecondaryOffset: number;
  maxScanBytes?: number;
  trailingTolerance: number;
}

const MIME_TO_FAMILY: Record<string, string> = {
  "application/zip": "zip",
  "application/x-zip-compressed": "zip",
  "application/java-archive": "zip",
  "image/jpeg": "jpeg",
  "image/png": "png",
  "application/pdf": "pdf",
  "text/html": "html",
};

const MAGIC_RULES: {
  family: string;
  mime: string;
  match: (buffer: Buffer) => boolean;
}[] = [
  {
    family: "jpeg",
    mime: "image/jpeg",
    match: (buffer) => buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xd8,
  },
  {
    family: "png",
    mime: "image/png",
    match: (buffer) =>
      buffer.length >= 8 &&
      buffer[0] === 0x89 &&
      buffer[1] === 0x50 &&
      buffer[2] === 0x4e &&
      buffer[3] === 0x47 &&
      buffer[4] === 0x0d &&
      buffer[5] === 0x0a &&
      buffer[6] === 0x1a &&
      buffer[7] === 0x0a,
  },
  {
    family: "pdf",
    mime: "application/pdf",
    match: (buffer) => buffer.length >= 5 && buffer.subarray(0, 5).toString("ascii") === "%PDF-",
  },
  {
    family: "zip",
    mime: "application/zip",
    match: (buffer) => buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4b,
  },
];

const makeHit = (family: string, mime: string, offset: number, evidence: string): FormatHit => ({
  family,
  mime,
  offset,
  evidence,
});

export class PolyglotScanner implements Scanner {
  readonly name = "polyglot";

  private readonly options: ResolvedPolyglotConfig;

  constructor(config: PolyglotConfig = {}) {
    this.options = {
      minSecondaryOffset: config.minSecondaryOffset ?? 0,
      maxScanBytes: config.maxScanBytes,
      trailingTolerance: config.trailingTolerance ?? DEFAULT_TRAILING_TOLERANCE,
    };
  }

  appliesTo(ctx: ScannerContext): boolean {
    return ctx.size > 0;
  }

  async scan(ctx: ScannerContext): Promise<Threat[]> {
    const threats: Threat[] = [];
    const buffer = await ctx.read();
    if (buffer.length === 0) return threats;

    const scanLength = Math.min(buffer.length, this.options.maxScanBytes ?? buffer.length);
    const slice = buffer.subarray(0, scanLength);

    const primary = this.resolvePrimary(ctx, slice);
    const secondary = this.findSecondaryFormats(slice, buffer.length, primary?.family);

    const distinctSecondaries = secondary.filter((hit) => {
      if (hit.offset < this.options.minSecondaryOffset) return false;
      if (primary && hit.family === primary.family) return false;
      return true;
    });

    if (primary && distinctSecondaries.length > 0) {
      const secondarySummary = distinctSecondaries
        .map((hit) => `${hit.mime} @ ${String(hit.offset)}`)
        .join(", ");

      threats.push(
        this.makeThreat(
          "POLYGLOT_DETECTED",
          "high",
          `File appears to match more than one format (${primary.mime} and ${secondarySummary})`,
          {
            primary,
            secondary: distinctSecondaries,
          },
        ),
      );
      return threats;
    }

    // No second format family, but unexplained payload after a complete image.
    const trailing = this.findTrailingContent(slice, primary?.family);
    if (trailing !== undefined) {
      threats.push(
        this.makeThreat(
          "POLYGLOT_TRAILING_CONTENT",
          "medium",
          `Unexpected trailing content after ${trailing.format} end marker (${String(trailing.trailingBytes)} bytes)`,
          trailing,
        ),
      );
    }

    return threats;
  }

  private resolvePrimary(ctx: ScannerContext, buffer: Buffer): FormatHit | undefined {
    if (ctx.detectedMime) {
      const family = MIME_TO_FAMILY[ctx.detectedMime] ?? ctx.detectedMime;
      return makeHit(family, ctx.detectedMime, 0, "detected-mime");
    }

    return this.detectPrimaryFromMagic(buffer);
  }

  private detectPrimaryFromMagic(buffer: Buffer): FormatHit | undefined {
    for (const rule of MAGIC_RULES) {
      if (rule.match(buffer)) {
        return makeHit(rule.family, rule.mime, 0, "magic");
      }
    }

    return undefined;
  }

  private findSecondaryFormats(
    slice: Buffer,
    fullLength: number,
    primaryFamily: string | undefined,
  ): FormatHit[] {
    const hits: FormatHit[] = [];

    if (!primaryFamily || !ZIP_FAMILIES.has(primaryFamily)) {
      const zip = this.findZipStructure(slice, fullLength);
      if (zip) hits.push(zip);
    }

    if (primaryFamily !== "pdf") {
      const pdf = this.findPdfMarker(slice);
      if (pdf) hits.push(pdf);
    }

    return hits;
  }

  /**
   * Look for a ZIP end-of-central-directory record near the end of the buffer.
   * ZIP-family formats keep directory metadata at the tail, which is why they
   * combine cleanly with formats that validate from the head.
   */
  private findZipStructure(slice: Buffer, fullLength: number): FormatHit | undefined {
    if (slice.length < 22) return undefined;

    const searchStart = Math.max(0, slice.length - ZIP_EOCD_WINDOW);
    for (let i = slice.length - 22; i >= searchStart; i--) {
      if (
        slice[i] !== 0x50 ||
        slice[i + 1] !== 0x4b ||
        slice[i + 2] !== 0x05 ||
        slice[i + 3] !== 0x06
      ) {
        continue;
      }

      const commentLength = slice.readUInt16LE(i + 20);
      const recordEnd = i + 22 + commentLength;
      // EOCD should sit at the end of the scanned bytes (and usually the file).
      if (recordEnd !== slice.length && recordEnd !== fullLength) continue;

      const centralDirectoryOffset = slice.readUInt32LE(i + 16);
      if (centralDirectoryOffset >= i) continue;

      return makeHit("zip", "application/zip", i, "zip-eocd");
    }

    return undefined;
  }

  private findPdfMarker(slice: Buffer): FormatHit | undefined {
    // Skip offset 0 — that would be the primary type, not a secondary face.
    const marker = Buffer.from("%PDF-");
    const index = slice.indexOf(marker, 1);
    if (index < 0) return undefined;

    return makeHit("pdf", "application/pdf", index, "pdf-header");
  }

  private findTrailingContent(
    slice: Buffer,
    primaryFamily: string | undefined,
  ): { format: string; endOffset: number; trailingBytes: number } | undefined {
    if (primaryFamily === "jpeg") {
      const endOffset = this.findJpegEndOffset(slice);
      if (endOffset === undefined) return undefined;
      const trailingBytes = slice.length - endOffset;
      if (trailingBytes <= this.options.trailingTolerance) return undefined;
      return { format: "jpeg", endOffset, trailingBytes };
    }

    if (primaryFamily === "png") {
      const endOffset = this.findPngEndOffset(slice);
      if (endOffset === undefined) return undefined;
      const trailingBytes = slice.length - endOffset;
      if (trailingBytes <= this.options.trailingTolerance) return undefined;
      return { format: "png", endOffset, trailingBytes };
    }

    return undefined;
  }

  private findJpegEndOffset(buffer: Buffer): number | undefined {
    if (buffer.length < 4 || buffer[0] !== 0xff || buffer[1] !== 0xd8) return undefined;

    for (let i = 2; i < buffer.length - 1; i++) {
      if (buffer[i] === 0xff && buffer[i + 1] === 0xd9) {
        return i + 2;
      }
    }

    return undefined;
  }

  private findPngEndOffset(buffer: Buffer): number | undefined {
    // IEND chunk: length(0) + "IEND" + CRC
    const iend = Buffer.from([
      0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
    ]);
    const index = buffer.indexOf(iend);
    if (index < 0) return undefined;
    return index + iend.length;
  }

  private makeThreat(
    code: string,
    severity: Severity,
    message: string,
    meta?: Record<string, unknown>,
  ): Threat {
    return {
      scanner: this.name,
      code,
      severity,
      message,
      meta,
    };
  }
}
