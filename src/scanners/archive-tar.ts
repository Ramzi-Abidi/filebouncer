import { compose, Readable, Transform, type TransformCallback } from "node:stream";
import { createGunzip } from "node:zlib";

import { createTarDecoder, type TarHeader } from "modern-tar";

import { ScanFailureError } from "../engine/scan-failure-error";
import type { Threat } from "../types";
import {
  ArchiveEntryPolicy,
  type ArchiveEntryType,
  type ArchivePolicyOptions,
  MIN_COMPRESSED_FOR_RATIO,
} from "./archive-entry";

const MAX_TAR_STRUCTURE_OVERHEAD = 16 * 1024 * 1024;

class TarExpansionLimitError extends Error {
  constructor(
    readonly limit: "size" | "ratio",
    readonly expandedSize: number,
  ) {
    super("Gzip-compressed TAR exceeded its expansion limit");
    this.name = "TarExpansionLimitError";
  }
}

export async function scanTarArchive(
  buffer: Buffer,
  compressed: boolean,
  options: ArchivePolicyOptions,
): Promise<Threat[]> {
  const policy = new ArchiveEntryPolicy(options);
  const source = Readable.from([buffer]);
  const tarStream = compressed
    ? compose(source, createGunzip(), createExpansionLimiter(buffer.length, options))
    : source;
  const entries = Readable.toWeb(tarStream).pipeThrough(createTarDecoder({ strict: true }));

  try {
    for await (const entry of entries) {
      const type = mapTarEntryType(entry.header);
      const stop = policy.inspectEntry(
        entry.header.name,
        type,
        type === "directory",
        entry.header.size,
        undefined,
        false,
      );
      await entry.body.cancel();
      if (stop) break;
    }

    return policy.finish(compressed ? buffer.length : undefined);
  } catch (error) {
    if (error instanceof TarExpansionLimitError) {
      if (error.limit === "size") return policy.reportSizeLimit(error.expandedSize);
      return policy.reportRatioLimit(error.expandedSize, buffer.length);
    }

    const format = compressed ? "tar.gz" : "TAR";
    throw new ScanFailureError(
      "CORRUPT_ARCHIVE",
      `Archive could not be parsed as a valid ${format}`,
      { cause: error },
    );
  }
}

function createExpansionLimiter(compressedSize: number, options: ArchivePolicyOptions): Transform {
  const maxExpandedSize = options.maxTotalUncompressed + MAX_TAR_STRUCTURE_OVERHEAD;
  const maxRatioSize =
    compressedSize >= MIN_COMPRESSED_FOR_RATIO
      ? compressedSize * options.maxRatio
      : Number.POSITIVE_INFINITY;
  let expandedSize = 0;

  return new Transform({
    transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback) {
      expandedSize += chunk.length;
      if (expandedSize > maxExpandedSize) {
        callback(new TarExpansionLimitError("size", expandedSize));
        return;
      }
      if (expandedSize > maxRatioSize) {
        callback(new TarExpansionLimitError("ratio", expandedSize));
        return;
      }
      callback(null, chunk);
    },
  });
}

function mapTarEntryType(header: TarHeader): ArchiveEntryType {
  switch (header.type) {
    case "directory":
      return "directory";
    case "symlink":
      return "symlink";
    case "link":
      return "hardlink";
    case "file":
    case undefined:
      return "file";
    default:
      return "other";
  }
}
