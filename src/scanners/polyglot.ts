import type { PolyglotConfig, Scanner, ScannerContext, Severity, Threat } from "../types";

const DEFAULT_TRAILING_TOLERANCE = 32;
/** EOCD is within this many bytes of the end (22-byte record + max comment). */
const ZIP_EOCD_WINDOW = 22 + 65_535;

const ZIP_FAMILIES = new Set(["zip"]);
/**
 * Formats whose job is to hold other files. A PDF stored inside one is normal
 * content, not a hidden second format, unless it sits where PDF readers look
 * for the header: Acrobat and pdf.js accept `%PDF-` within the first 1024 bytes.
 */
const CONTAINER_MIMES = new Set([
  "application/x-tar",
  "application/gzip",
  "application/x-7z-compressed",
  "application/x-rar-compressed",
  "application/vnd.rar",
  "application/x-cfb",
  "application/x-msi",
]);
const PDF_HEADER_WINDOW = 1024;
const PDF_MARKER = Buffer.from("%PDF-");
const ZIP_CONTAINER_EXTENSIONS = new Set([
  "zip",
  "jar",
  "apk",
  "xpi",
  "epub",
  "docx",
  "docm",
  "dotx",
  "dotm",
  "xlsx",
  "xlsm",
  "xltx",
  "xltm",
  "pptx",
  "pptm",
  "ppsx",
  "ppsm",
  "potx",
  "potm",
  "odt",
  "ott",
  "ods",
  "ots",
  "odp",
  "otp",
  "odg",
  "otg",
  "vsdx",
  "3mf",
]);

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

const JPEG_SOI = 0xd8;
const JPEG_EOI = 0xd9;
const JPEG_SOS = 0xda;

/** Markers that carry no length field: TEM (0x01) and restart markers RST0–RST7. */
const isStandaloneJpegMarker = (marker: number): boolean =>
  marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7);

/**
 * Skip over entropy-coded image data that follows a start-of-scan header.
 * Inside it, a literal 0xFF byte is written as `FF 00` and restart markers
 * (`FF D0`–`FF D7`) may appear; any other `FF xx` is the next real marker.
 * Returns the offset of that marker, or `undefined` if the data is truncated.
 */
const findJpegScanEnd = (buffer: Buffer, start: number): number | undefined => {
  for (let i = start; i < buffer.length - 1; i++) {
    if (buffer[i] !== 0xff) continue;
    const next = buffer[i + 1]!;
    if (next === 0x00 || next === 0xff || isStandaloneJpegMarker(next)) continue;
    return i;
  }
  return undefined;
};

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
    const secondary = this.findSecondaryFormats(slice, buffer.length, primary);

    const distinctSecondaries = secondary.filter((hit) => {
      if (hit.offset < this.options.minSecondaryOffset) return false;
      if (primary?.family === hit.family) return false;
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
      const family =
        ctx.detectedExt && ZIP_CONTAINER_EXTENSIONS.has(ctx.detectedExt)
          ? "zip"
          : (MIME_TO_FAMILY[ctx.detectedMime] ?? ctx.detectedMime);
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
    primary: FormatHit | undefined,
  ): FormatHit[] {
    const hits: FormatHit[] = [];
    const primaryFamily = primary?.family;

    if (!primaryFamily || !ZIP_FAMILIES.has(primaryFamily)) {
      const zip = this.findZipStructure(slice, fullLength);
      if (zip) hits.push(zip);
    }

    if (primaryFamily !== "pdf") {
      const isContainer =
        primary !== undefined &&
        (ZIP_FAMILIES.has(primary.family) || CONTAINER_MIMES.has(primary.mime));
      const pdf = this.findPdfMarker(
        isContainer ? slice.subarray(0, PDF_HEADER_WINDOW + PDF_MARKER.length) : slice,
      );
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
    const index = slice.indexOf(PDF_MARKER, 1);
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

  /**
   * Walk the JPEG segment by segment to find the real end-of-image (EOI) marker.
   *
   * A naive search for the first `FF D9` is wrong: camera photos embed a full
   * thumbnail JPEG inside the EXIF segment, and that thumbnail has its own EOI.
   * Jumping over each segment by its declared length skips such nested data.
   *
   * Returns the offset just past the EOI, or `undefined` if the structure is
   * malformed or truncated.
   */
  private findJpegEndOffset(buffer: Buffer): number | undefined {
    if (buffer.length < 4 || buffer[0] !== 0xff || buffer[1] !== 0xd8) return undefined;

    let i = 2;
    while (i < buffer.length) {
      if (buffer[i] !== 0xff) return undefined;
      // Any number of 0xFF fill bytes may precede a marker.
      while (i < buffer.length && buffer[i] === 0xff) i++;
      if (i >= buffer.length) return undefined;

      const marker = buffer[i]!;
      i++;

      if (marker === JPEG_EOI) return i;
      if (isStandaloneJpegMarker(marker)) continue;
      if (marker === 0x00 || marker === JPEG_SOI) return undefined;

      if (i + 2 > buffer.length) return undefined;
      const segmentLength = buffer.readUInt16BE(i);
      if (segmentLength < 2) return undefined;
      i += segmentLength;

      if (marker === JPEG_SOS) {
        const scanEnd = findJpegScanEnd(buffer, i);
        if (scanEnd === undefined) return undefined;
        i = scanEnd;
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
