import { fromBufferPromise } from "yauzl";

import { ScanFailureError } from "../engine/scan-failure-error";
import type { Threat } from "../types";
import { ArchiveEntryPolicy, type ArchivePolicyOptions } from "./archive-entry";

const YAUZL_STRONG_ENCRYPTION_ERROR = "strong encryption is not supported";
const UNIX_VERSION_MADE_BY = 3;
const S_IFMT = 0o170000;
const S_IFLNK = 0o120000;

export async function scanZipArchive(
  buffer: Buffer,
  options: ArchivePolicyOptions,
): Promise<Threat[]> {
  let zipfile;
  try {
    zipfile = await fromBufferPromise(buffer, { lazyEntries: true, decodeStrings: false });
  } catch (error) {
    throw new ScanFailureError("CORRUPT_ARCHIVE", "Archive could not be parsed as a valid ZIP", {
      cause: error,
    });
  }

  const policy = new ArchiveEntryPolicy(options);

  try {
    for await (const entry of zipfile.eachEntry()) {
      const fileName = decodeFileName(entry.fileName);
      const mode = entry.externalFileAttributes >>> 16;
      const isUnixSymlink = entry.versionMadeBy >> 8 === UNIX_VERSION_MADE_BY;
      const type = isUnixSymlink && (mode & S_IFMT) === S_IFLNK ? "symlink" : "file";
      const stop = policy.inspectEntry(
        fileName,
        type,
        fileName.endsWith("/"),
        entry.uncompressedSize,
        entry.compressedSize,
        entry.isEncrypted(),
      );
      if (stop) break;
    }

    return policy.finish();
  } catch (error) {
    if (error instanceof Error && error.message === YAUZL_STRONG_ENCRYPTION_ERROR) {
      return policy.reportStrongEncryption();
    }

    throw new ScanFailureError("CORRUPT_ARCHIVE", "Archive entries could not be read", {
      cause: error,
    });
  } finally {
    zipfile.close();
  }
}

function decodeFileName(fileName: string | Buffer): string {
  const raw = Buffer.isBuffer(fileName) ? fileName.toString("utf8") : fileName;
  return raw.replaceAll("\\", "/");
}
