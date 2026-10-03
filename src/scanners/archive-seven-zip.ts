import { Worker } from "node:worker_threads";

import { ScanFailureError } from "../engine/scan-failure-error";
import type { Threat } from "../types";
import {
  ArchiveEntryPolicy,
  type ArchiveEntryType,
  type ArchivePolicyOptions,
} from "./archive-entry";

const SEVEN_ZIP_LIST_TIMEOUT_MS = 30_000;
const SEVEN_ZIP_PASSWORD_SENTINEL = "__filebouncer_no_password__";
const RELEVANT_FIELDS: Readonly<Record<string, true>> = {
  Path: true,
  Size: true,
  "Packed Size": true,
  Attributes: true,
  Encrypted: true,
  Folder: true,
  "Symbolic Link": true,
  "Hard Link": true,
};
const SEVEN_ZIP_WORKER_SOURCE = String.raw`
const { parentPort, workerData } = require("node:worker_threads");

(async () => {
  // The package URL is resolved by the parent so pnpm's nested dependency layout works.
  const SevenZip = (await import(workerData.moduleUrl)).default;
  const module = await SevenZip({
    noExitRuntime: true,
    print: (line) => parentPort.postMessage({ type: "stdout", line: String(line) }),
    printErr: (line) => parentPort.postMessage({ type: "stderr", line: String(line) }),
  });
  module.FS.writeFile("archive.7z", workerData.archive);
  module.callMain([
    "l",
    "-slt",
    "-ba",
    "-bsp0",
    "-p${SEVEN_ZIP_PASSWORD_SENTINEL}",
    "archive.7z",
  ]);
  parentPort.postMessage({ type: "done" });
})().catch((error) => {
  const message = String(error?.stack ?? error);
  parentPort.postMessage({
    type: /^\d+$/.test(message) ? "runtime-exit" : "error",
    message,
  });
});
`;

interface SevenZipWorkerMessage {
  type: "stdout" | "stderr" | "done" | "runtime-exit" | "error";
  line?: string;
  message?: string;
}

interface SevenZipRecord {
  path: string;
  size: number;
  packedSize?: number;
  attributes?: string;
  encrypted: boolean;
  folder: boolean;
  symbolicLink: boolean;
  hardLink: boolean;
}

export function scanSevenZipArchive(
  buffer: Buffer,
  options: ArchivePolicyOptions,
): Promise<Threat[]> {
  const policy = new ArchiveEntryPolicy(options);
  const parser = new SevenZipListingParser((record) => {
    const type = classifyEntry(record);
    return policy.inspectEntry(
      record.path,
      type,
      record.folder,
      record.size,
      record.packedSize,
      record.encrypted,
    );
  });

  return new Promise<Threat[]>((resolve, reject) => {
    const errors: string[] = [];
    let completed = false;
    let runtimeExited = false;
    let settled = false;
    const worker = new Worker(SEVEN_ZIP_WORKER_SOURCE, {
      eval: true,
      workerData: {
        archive: buffer,
        moduleUrl: import.meta.resolve("7z-wasm"),
      },
      resourceLimits: {
        maxOldGenerationSizeMb: 64,
        maxYoungGenerationSizeMb: 16,
        stackSizeMb: 4,
      },
    });

    const timeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      void worker.terminate();
      reject(
        new ScanFailureError(
          "ARCHIVE_SCAN_TIMEOUT",
          `7z metadata inspection exceeded ${String(SEVEN_ZIP_LIST_TIMEOUT_MS)}ms`,
        ),
      );
    }, SEVEN_ZIP_LIST_TIMEOUT_MS);

    const resolveAndTerminate = (threats: Threat[]) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      void worker.terminate();
      resolve(threats);
    };

    const rejectAndTerminate = (error: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      void worker.terminate();
      reject(error);
    };

    worker.on("message", (message: SevenZipWorkerMessage) => {
      if (settled) return;
      if (message.type === "stderr") {
        if (message.line && errors.length < 20) errors.push(message.line);
        return;
      }
      if (message.type === "error") {
        rejectAndTerminate(new Error(message.message ?? "7z worker failed"));
        return;
      }
      if (message.type === "runtime-exit") {
        runtimeExited = true;
        return;
      }
      if (message.type === "done") {
        completed = true;
        return;
      }
      if (message.line === undefined) return;

      try {
        if (parser.push(message.line)) {
          resolveAndTerminate(policy.finish(buffer.length));
        }
      } catch (error) {
        rejectAndTerminate(
          new ScanFailureError("CORRUPT_ARCHIVE", "7z entry metadata is malformed", {
            cause: error,
          }),
        );
      }
    });

    worker.on("error", rejectAndTerminate);
    worker.on("exit", (exitCode) => {
      if (settled) return;
      clearTimeout(timeout);

      try {
        parser.finish();
      } catch (error) {
        rejectAndTerminate(
          new ScanFailureError("CORRUPT_ARCHIVE", "7z entry metadata is malformed", {
            cause: error,
          }),
        );
        return;
      }

      if (exitCode === 0 && completed) {
        settled = true;
        resolve(policy.finish(buffer.length));
        return;
      }
      if ((exitCode === 1 || runtimeExited) && parser.entryCount === 0) {
        settled = true;
        resolve(policy.reportStrongEncryption());
        return;
      }

      settled = true;
      const detail = errors.filter(Boolean).join("; ");
      reject(
        new ScanFailureError(
          "CORRUPT_ARCHIVE",
          detail.length > 0
            ? `Archive could not be parsed as a valid 7z: ${detail}`
            : "Archive could not be parsed as a valid 7z",
        ),
      );
    });
  });
}

class SevenZipListingParser {
  private readonly fields = new Map<string, string>();
  entryCount = 0;

  constructor(private readonly onEntry: (record: SevenZipRecord) => boolean) {}

  push(line: string): boolean {
    if (line.length === 0) return this.flushRecord();
    if (line.includes("\b")) throw new Error("Unexpected progress output");

    const separator = line.indexOf(" = ");
    if (separator <= 0) throw new Error(`Unexpected 7z output: ${line}`);
    const key = line.slice(0, separator);
    const value = line.slice(separator + 3);
    if (RELEVANT_FIELDS[key] !== true) return false;
    if (this.fields.has(key)) throw new Error(`Duplicate 7z metadata field: ${key}`);
    this.fields.set(key, value);
    return false;
  }

  finish(): boolean {
    return this.flushRecord();
  }

  private flushRecord(): boolean {
    if (this.fields.size === 0) return false;

    const path = this.fields.get("Path");
    const size = parseSize(this.fields.get("Size"), "Size");
    if (path === undefined) throw new Error("7z entry is missing Path");

    const packedSizeValue = this.fields.get("Packed Size");
    const record: SevenZipRecord = {
      path,
      size,
      packedSize:
        packedSizeValue === undefined || packedSizeValue.length === 0
          ? undefined
          : parseSize(packedSizeValue, "Packed Size"),
      attributes: this.fields.get("Attributes"),
      encrypted: this.fields.get("Encrypted") === "+",
      folder: this.fields.get("Folder") === "+",
      symbolicLink: this.fields.has("Symbolic Link"),
      hardLink: this.fields.has("Hard Link"),
    };
    this.fields.clear();
    this.entryCount += 1;
    return this.onEntry(record);
  }
}

function parseSize(value: string | undefined, field: string): number {
  if (value === undefined || !/^\d+$/.test(value)) {
    throw new Error(`Invalid 7z ${field}`);
  }
  const size = Number(value);
  if (!Number.isSafeInteger(size)) throw new Error(`7z ${field} exceeds safe integer range`);
  return size;
}

function classifyEntry(record: SevenZipRecord): ArchiveEntryType {
  const unixMode = record.attributes
    ?.split(/\s+/)
    .find((part) => part.length === 10 && /^[dl-]/.test(part));
  if (record.hardLink) return "hardlink";
  if (record.symbolicLink || unixMode?.startsWith("l")) return "symlink";
  if (record.folder || unixMode?.startsWith("d")) return "directory";
  return "file";
}
