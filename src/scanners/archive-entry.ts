import type { Severity, Threat } from "../types";

const ARCHIVE_SCANNER_NAME = "archive";
export const MIN_COMPRESSED_FOR_RATIO = 64;

export type ArchiveEntryType = "file" | "directory" | "symlink" | "hardlink" | "other";

export interface ArchivePolicyOptions {
  maxEntries: number;
  maxTotalUncompressed: number;
  maxRatio: number;
  allowSymlinks: boolean;
}

export class ArchiveEntryPolicy {
  private readonly threats: Threat[] = [];
  private entryCount = 0;
  private totalUncompressed = 0;
  private totalCompressed = 0;

  constructor(private readonly options: ArchivePolicyOptions) {}

  inspectEntry(
    fileName: string,
    type: ArchiveEntryType,
    isDirectory: boolean,
    uncompressedSize: number,
    compressedSize: number | undefined,
    encrypted: boolean,
  ): boolean {
    this.entryCount += 1;

    if (encrypted) {
      this.threats.push(
        makeThreat("ENCRYPTED_ENTRY", "high", `Archive entry is encrypted: ${fileName}`, fileName),
      );
    }

    this.checkEntryName(fileName);
    this.checkLink(fileName, type);

    if (!isDirectory) {
      this.totalUncompressed += uncompressedSize;
      if (compressedSize !== undefined) {
        this.totalCompressed += compressedSize;
        this.checkEntryRatio(compressedSize, uncompressedSize, fileName);
      }
    }

    if (this.entryCount > this.options.maxEntries) {
      this.threats.push(
        makeThreat(
          "ARCHIVE_ENTRY_LIMIT",
          "critical",
          `Archive has more than ${String(this.options.maxEntries)} entries`,
          undefined,
          { entryCount: this.entryCount, maxEntries: this.options.maxEntries },
        ),
      );
      return true;
    }

    if (this.totalUncompressed > this.options.maxTotalUncompressed) {
      this.reportSizeLimit(this.totalUncompressed);
      return true;
    }

    return false;
  }

  reportStrongEncryption(): Threat[] {
    this.threats.push(
      makeThreat(
        "ENCRYPTED_ENTRY",
        "high",
        "Archive contains a strongly encrypted entry",
        undefined,
      ),
    );
    return this.threats;
  }

  finish(aggregateCompressedSize?: number): Threat[] {
    const totalCompressed = aggregateCompressedSize ?? this.totalCompressed;
    if (
      totalCompressed >= MIN_COMPRESSED_FOR_RATIO &&
      this.totalUncompressed / totalCompressed > this.options.maxRatio
    ) {
      this.reportRatioLimit(this.totalUncompressed, totalCompressed);
    }

    return this.threats;
  }

  reportSizeLimit(totalUncompressed: number): Threat[] {
    this.threats.push(
      makeThreat(
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
    return this.threats;
  }

  reportRatioLimit(totalUncompressed: number, totalCompressed: number): Threat[] {
    this.threats.push(
      makeThreat(
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
    return this.threats;
  }

  private checkEntryName(fileName: string): void {
    if (fileName.includes("\0")) {
      this.threats.push(
        makeThreat(
          "UNSAFE_ENTRY_PATH",
          "critical",
          "Archive entry name contains a null byte",
          fileName,
        ),
      );
      return;
    }

    if (fileName.startsWith("/") || /^[A-Za-z]:[/\\]/.test(fileName)) {
      this.threats.push(
        makeThreat(
          "UNSAFE_ABS_PATH",
          "high",
          `Archive entry uses an absolute path: ${fileName}`,
          fileName,
        ),
      );
    }

    const segments = fileName.split(/[/\\]/);
    if (segments.some((segment) => segment === "..")) {
      this.threats.push(
        makeThreat(
          "UNSAFE_ENTRY_PATH",
          "critical",
          `Archive entry path leaves the destination directory: ${fileName}`,
          fileName,
        ),
      );
    }
  }

  private checkLink(fileName: string, type: ArchiveEntryType): void {
    if (type === "symlink" && this.options.allowSymlinks) return;
    if (type !== "symlink" && type !== "hardlink") return;

    this.threats.push(
      makeThreat("LINK_ENTRY", "high", `Archive contains a link entry: ${fileName}`, fileName),
    );
  }

  private checkEntryRatio(
    compressedSize: number,
    uncompressedSize: number,
    fileName: string,
  ): void {
    if (compressedSize < MIN_COMPRESSED_FOR_RATIO) return;
    if (uncompressedSize / compressedSize <= this.options.maxRatio) return;

    this.threats.push(
      makeThreat(
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
}

function makeThreat(
  code: string,
  severity: Severity,
  message: string,
  path: string | undefined,
  meta?: Record<string, unknown>,
): Threat {
  const threat: Threat = {
    scanner: ARCHIVE_SCANNER_NAME,
    code,
    severity,
    message,
  };
  if (path !== undefined) threat.path = path;
  if (meta !== undefined) threat.meta = meta;
  return threat;
}
