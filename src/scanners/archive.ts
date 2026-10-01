import { ScanFailureError } from "../engine/scan-failure-error";
import type { ArchiveConfig, Scanner, ScannerContext, Threat } from "../types";
import type { ArchivePolicyOptions } from "./archive-entry";
import { scanTarArchive } from "./archive-tar";
import { scanZipArchive } from "./archive-zip";

const ZIP_EXTENSIONS = ["zip", "jar", "apk"];
const ZIP_MIMES = ["application/zip", "application/x-zip-compressed", "application/java-archive"];
const TAR_MIMES = ["application/x-tar"];
const TAR_GZIP_MIMES = ["application/x-compressed-tar", "application/x-tgz"];

const DEFAULT_MAX_ENTRIES = 10_000;
const DEFAULT_MAX_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024;
const DEFAULT_MAX_RATIO = 100;

type ArchiveFormat = "zip" | "tar" | "tar-gzip";

export class ArchiveScanner implements Scanner {
  readonly name = "archive";

  private readonly options: ArchivePolicyOptions;

  constructor(config: ArchiveConfig = {}) {
    this.options = {
      maxEntries: config.maxEntries ?? DEFAULT_MAX_ENTRIES,
      maxTotalUncompressed: config.maxTotalUncompressed ?? DEFAULT_MAX_TOTAL_UNCOMPRESSED,
      maxRatio: config.maxRatio ?? DEFAULT_MAX_RATIO,
      allowSymlinks: config.allowSymlinks ?? false,
    };
  }

  appliesTo(ctx: ScannerContext): boolean {
    return resolveArchiveFormat(ctx) !== undefined;
  }

  async scan(ctx: ScannerContext): Promise<Threat[]> {
    const format = resolveArchiveFormat(ctx);
    if (format === undefined) return [];

    const buffer = await ctx.read();
    if (buffer.length === 0) {
      throw new ScanFailureError("CORRUPT_ARCHIVE", "Archive is empty");
    }

    switch (format) {
      case "zip":
        return scanZipArchive(buffer, this.options);
      case "tar":
        return scanTarArchive(buffer, false, this.options);
      case "tar-gzip":
        return scanTarArchive(buffer, true, this.options);
    }
  }
}

function resolveArchiveFormat(ctx: ScannerContext): ArchiveFormat | undefined {
  const filename = ctx.filename?.split(/[/\\]/).pop()?.toLowerCase();
  if (filename?.endsWith(".tar.gz") || filename?.endsWith(".tgz")) return "tar-gzip";

  const extensionFormat = formatFromExtension(ctx.extension);
  if (extensionFormat !== undefined) return extensionFormat;

  const detectedFormat = formatFromExtension(ctx.detectedExt);
  if (detectedFormat !== undefined) return detectedFormat;

  const detectedMimeFormat = formatFromMime(ctx.detectedMime);
  if (detectedMimeFormat !== undefined) return detectedMimeFormat;

  return formatFromMime(ctx.declaredMime);
}

function formatFromExtension(extension: string | undefined): ArchiveFormat | undefined {
  if (extension === undefined) return undefined;
  const normalized = extension.toLowerCase();
  if (ZIP_EXTENSIONS.includes(normalized)) return "zip";
  if (normalized === "tar") return "tar";
  if (normalized === "tar.gz" || normalized === "tgz") return "tar-gzip";
  return undefined;
}

function formatFromMime(mime: string | undefined): ArchiveFormat | undefined {
  if (mime === undefined) return undefined;
  const normalized = mime.split(";")[0]!.trim().toLowerCase();
  if (ZIP_MIMES.includes(normalized)) return "zip";
  if (TAR_MIMES.includes(normalized)) return "tar";
  if (TAR_GZIP_MIMES.includes(normalized)) return "tar-gzip";
  return undefined;
}
