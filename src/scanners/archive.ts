import { fromBufferPromise } from "yauzl";

import { ScanFailureError } from "../engine/scan-failure-error";
import type { ArchiveConfig, Scanner, ScannerContext, Severity, Threat } from "../types";

const ARCHIVE_EXTENSIONS = ["zip", "jar", "apk"];
const ARCHIVE_MIMES = [
  "application/zip",
  "application/x-zip-compressed",
  "application/java-archive",
];

const DEFAULT_MAX_ENTRIES = 10_000;
const DEFAULT_MAX_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024;
const DEFAULT_MAX_RATIO = 100;
const MIN_COMPRESSED_FOR_RATIO = 64;
const YAUZL_STRONG_ENCRYPTION_ERROR = "strong encryption is not supported";

const UNIX_VERSION_MADE_BY = 3;
const S_IFMT = 0o170000;
const S_IFLNK = 0o120000;

interface ResolvedArchiveConfig {
  maxEntries: number;
  maxTotalUncompressed: number;
  maxRatio: number;
  maxDepth: number;
  allowSymlinks: boolean;
}

export class ArchiveScanner implements Scanner {
  readonly name = "archive";

  private readonly options: ResolvedArchiveConfig;

  constructor(config: ArchiveConfig = {}) {
    this.options = {
      maxEntries: config.maxEntries ?? DEFAULT_MAX_ENTRIES,
      maxTotalUncompressed: config.maxTotalUncompressed ?? DEFAULT_MAX_TOTAL_UNCOMPRESSED,
      maxRatio: config.maxRatio ?? DEFAULT_MAX_RATIO,
      maxDepth: config.maxDepth ?? 0,
      allowSymlinks: config.allowSymlinks ?? false,
    };
  }

  appliesTo(ctx: ScannerContext): boolean {
    if (ctx.extension && ARCHIVE_EXTENSIONS.includes(ctx.extension)) return true;
    if (ctx.detectedMime && ArchiveScanner.isArchiveMime(ctx.detectedMime)) return true;
    if (ctx.declaredMime && ArchiveScanner.isArchiveMime(ctx.declaredMime)) return true;
    return false;
  }

  async scan(ctx: ScannerContext): Promise<Threat[]> {
    const threats: Threat[] = [];
    const buffer = await ctx.read();
    if (buffer.length === 0) {
      throw new ScanFailureError("CORRUPT_ARCHIVE", "Archive is empty");
    }

    let zipfile;
    try {
      zipfile = await fromBufferPromise(buffer, { lazyEntries: true, decodeStrings: false });
    } catch (err) {
      throw new ScanFailureError("CORRUPT_ARCHIVE", "Archive could not be parsed as a valid ZIP", {
        cause: err,
      });
    }

    let entryCount = 0;
    let totalUncompressed = 0;
    let totalCompressed = 0;

    try {
      for await (const entry of zipfile.eachEntry()) {
        entryCount += 1;
        const fileName = ArchiveScanner.decodeFileName(entry.fileName);

        if (entry.isEncrypted()) {
          threats.push(
            this.makeThreat(
              "ENCRYPTED_ENTRY",
              "high",
              `Archive entry is encrypted: ${fileName}`,
              fileName,
            ),
          );
        }

        this.checkEntryName(fileName, threats);
        this.checkSymlink(entry.versionMadeBy, entry.externalFileAttributes, fileName, threats);

        if (!fileName.endsWith("/")) {
          totalUncompressed += entry.uncompressedSize;
          totalCompressed += entry.compressedSize;

          this.checkEntryRatio(entry.compressedSize, entry.uncompressedSize, fileName, threats);
        }

        if (entryCount > this.options.maxEntries) {
          threats.push(
            this.makeThreat(
              "ARCHIVE_ENTRY_LIMIT",
              "critical",
              `Archive has more than ${String(this.options.maxEntries)} entries`,
              undefined,
              { entryCount, maxEntries: this.options.maxEntries },
            ),
          );
          break;
        }

        if (totalUncompressed > this.options.maxTotalUncompressed) {
          threats.push(
            this.makeThreat(
              "ARCHIVE_SIZE_LIMIT",
              "critical",
              `Archive uncompressed size exceeds ${String(this.options.maxTotalUncompressed)} bytes`,
              undefined,
              {
                totalUncompressed,
                maxTotalUncompressed: this.options.maxTotalUncompressed,
              },
            ),
          );
          break;
        }
      }

      if (
        totalCompressed >= MIN_COMPRESSED_FOR_RATIO &&
        totalUncompressed / totalCompressed > this.options.maxRatio
      ) {
        threats.push(
          this.makeThreat(
            "ARCHIVE_RATIO_LIMIT",
            "critical",
            `Archive compression ratio exceeds ${String(this.options.maxRatio)}:1`,
            undefined,
            {
              ratio: totalUncompressed / totalCompressed,
              maxRatio: this.options.maxRatio,
              totalUncompressed,
              totalCompressed,
            },
          ),
        );
      }
    } catch (error) {
      if (error instanceof Error && error.message === YAUZL_STRONG_ENCRYPTION_ERROR) {
        threats.push(
          this.makeThreat(
            "ENCRYPTED_ENTRY",
            "high",
            "Archive contains a strongly encrypted entry",
            undefined,
          ),
        );
        return threats;
      }

      throw new ScanFailureError("CORRUPT_ARCHIVE", "Archive entries could not be read", {
        cause: error,
      });
    } finally {
      zipfile.close();
    }

    return threats;
  }

  private checkEntryName(fileName: string, threats: Threat[]): void {
    if (fileName.includes("\0")) {
      threats.push(
        this.makeThreat(
          "UNSAFE_ENTRY_PATH",
          "critical",
          "Archive entry name contains a null byte",
          fileName,
        ),
      );
      return;
    }

    if (fileName.startsWith("/") || /^[A-Za-z]:[/\\]/.test(fileName)) {
      threats.push(
        this.makeThreat(
          "UNSAFE_ABS_PATH",
          "high",
          `Archive entry uses an absolute path: ${fileName}`,
          fileName,
        ),
      );
    }

    const segments = fileName.split(/[/\\]/);
    if (segments.some((segment) => segment === "..")) {
      threats.push(
        this.makeThreat(
          "UNSAFE_ENTRY_PATH",
          "critical",
          `Archive entry path leaves the destination directory: ${fileName}`,
          fileName,
        ),
      );
    }
  }

  private checkSymlink(
    versionMadeBy: number,
    externalFileAttributes: number,
    fileName: string,
    threats: Threat[],
  ): void {
    if (this.options.allowSymlinks) return;
    if (!ArchiveScanner.isSymlink(versionMadeBy, externalFileAttributes)) return;

    threats.push(
      this.makeThreat("LINK_ENTRY", "high", `Archive contains a link entry: ${fileName}`, fileName),
    );
  }

  private checkEntryRatio(
    compressedSize: number,
    uncompressedSize: number,
    fileName: string,
    threats: Threat[],
  ): void {
    if (compressedSize < MIN_COMPRESSED_FOR_RATIO) return;
    if (uncompressedSize / compressedSize <= this.options.maxRatio) return;

    threats.push(
      this.makeThreat(
        "ARCHIVE_RATIO_LIMIT",
        "critical",
        `Archive entry compression ratio exceeds ${String(this.options.maxRatio)}:1`,
        fileName,
        {
          ratio: uncompressedSize / compressedSize,
          maxRatio: this.options.maxRatio,
          compressedSize,
          uncompressedSize,
        },
      ),
    );
  }

  private makeThreat(
    code: string,
    severity: Severity,
    message: string,
    path: string | undefined,
    meta?: Record<string, unknown>,
  ): Threat {
    const threat: Threat = {
      scanner: this.name,
      code,
      severity,
      message,
    };
    if (path !== undefined) threat.path = path;
    if (meta !== undefined) threat.meta = meta;
    return threat;
  }

  private static isArchiveMime(mime: string): boolean {
    const normalized = mime.split(";")[0]!.trim().toLowerCase();
    return ARCHIVE_MIMES.includes(normalized);
  }

  private static decodeFileName(fileName: string | Buffer): string {
    const raw = Buffer.isBuffer(fileName) ? fileName.toString("utf8") : fileName;
    return raw.replaceAll("\\", "/");
  }

  private static isSymlink(versionMadeBy: number, externalFileAttributes: number): boolean {
    if (versionMadeBy >> 8 !== UNIX_VERSION_MADE_BY) return false;
    const mode = externalFileAttributes >>> 16;
    return (mode & S_IFMT) === S_IFLNK;
  }
}
