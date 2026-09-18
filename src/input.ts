import { promises as fs } from "node:fs";
import path from "node:path";
import { Readable } from "node:stream";

import { FileBouncerError } from "./types.js";

/**
 * Raw inputs accepted by the engine. Buffer-first: any input that isn't
 * already a `Buffer` is drained or copied into one during normalization.
 */
export type RawInput =
  | Buffer
  | Uint8Array
  | ArrayBuffer
  | Blob
  | Readable
  | ReadableStream<Uint8Array>
  | { path: string };

export interface NormalizeOptions {
  /** Original filename. Falls back to source-supplied name (Blob/File/path). */
  filename?: string;
  /** MIME claimed by the caller. Falls back to `Blob.type` if present. */
  declaredMime?: string;
  /**
   * Hard cap on input size in bytes. When exceeded, normalize throws
   * {@link InputTooLargeError}. The engine catches this and converts it
   * into a `FILE_TOO_LARGE` threat on the {@link ScanResult}.
   */
  maxBytes?: number;
}

export interface NormalizedInput {
  size: number;
  filename?: string;
  declaredMime?: string;
  /** Lowercased extension without leading dot, derived from `filename`. */
  extension?: string;
  /** Returns the full input buffer. Memoized; safe to call repeatedly. */
  read(): Promise<Buffer>;
}

/**
 * Thrown by {@link normalizeInput} when the input exceeds
 * `NormalizeOptions.maxBytes`. Distinct from {@link FileBouncerError}
 * so the engine can detect it specifically and convert it to a
 * structured threat instead of propagating.
 */
export class InputTooLargeError extends Error {
  readonly observedAtLeast: number;
  readonly maxBytes: number;

  constructor(observedAtLeast: number, maxBytes: number) {
    super(
      `Input exceeded maxBytes (${String(maxBytes)}); observed at least ${String(observedAtLeast)} bytes`,
    );
    this.name = "InputTooLargeError";
    this.observedAtLeast = observedAtLeast;
    this.maxBytes = maxBytes;
  }
}

/**
 * Normalize any supported input into a {@link NormalizedInput}.
 *
 * - Throws {@link InputTooLargeError} if `opts.maxBytes` is set and exceeded.
 * - Throws {@link FileBouncerError} if `raw` is not a supported input type.
 *
 * Streams and paths are read eagerly so `size` is always known by the time this
 * function resolves.
 */
export async function normalizeInput(
  raw: RawInput,
  opts: NormalizeOptions = {},
): Promise<NormalizedInput> {
  const { maxBytes } = opts;

  if (Buffer.isBuffer(raw)) {
    enforceCap(raw.length, maxBytes);
    return makeBufferInput(raw, opts.filename, opts.declaredMime);
  }

  if (raw instanceof Uint8Array) {
    enforceCap(raw.byteLength, maxBytes);
    return makeBufferInput(Buffer.from(raw), opts.filename, opts.declaredMime);
  }

  if (raw instanceof ArrayBuffer) {
    enforceCap(raw.byteLength, maxBytes);
    return makeBufferInput(Buffer.from(raw), opts.filename, opts.declaredMime);
  }

  if (typeof Blob !== "undefined" && raw instanceof Blob) {
    return normalizeBlob(raw, opts);
  }

  if (isPathInput(raw)) {
    return normalizePath(raw.path, opts);
  }

  if (typeof ReadableStream !== "undefined" && raw instanceof ReadableStream) {
    const buf = await drainWebStream(raw, maxBytes);
    return makeBufferInput(buf, opts.filename, opts.declaredMime);
  }

  if (raw instanceof Readable) {
    const buf = await drainNodeReadable(raw, maxBytes);
    return makeBufferInput(buf, opts.filename, opts.declaredMime);
  }

  throw new FileBouncerError(
    `Unsupported input type: ${describe(raw)}. Expected Buffer, Uint8Array, ArrayBuffer, Blob, File, Readable, ReadableStream, or { path }.`,
  );
}

function makeBufferInput(
  buf: Buffer,
  filename: string | undefined,
  declaredMime: string | undefined,
): NormalizedInput {
  const extension = parseExtension(filename);
  return {
    size: buf.length,
    filename,
    declaredMime,
    extension,
    read: () => Promise.resolve(buf),
  };
}

function normalizeBlob(blob: Blob, opts: NormalizeOptions): NormalizedInput {
  enforceCap(blob.size, opts.maxBytes);

  const filename = opts.filename ?? (hasName(blob) ? blob.name : undefined);
  const declaredMime = opts.declaredMime ?? (blob.type || undefined);
  const extension = parseExtension(filename);
  let cached: Buffer | undefined;

  return {
    size: blob.size,
    filename,
    declaredMime,
    extension,
    read: async () => {
      if (cached === undefined) {
        cached = Buffer.from(await blob.arrayBuffer());
      }
      return cached;
    },
  };
}

async function normalizePath(filePath: string, opts: NormalizeOptions): Promise<NormalizedInput> {
  const stats = await fs.stat(filePath);
  if (!stats.isFile()) {
    throw new FileBouncerError(`Path is not a regular file: ${filePath}`);
  }
  enforceCap(stats.size, opts.maxBytes);

  const handle = await fs.open(filePath, "r");
  try {
    const openedStats = await handle.stat();
    if (!openedStats.isFile()) {
      throw new FileBouncerError(`Path is not a regular file: ${filePath}`);
    }
    enforceCap(openedStats.size, opts.maxBytes);

    const chunks: Buffer[] = [];
    let total = 0;
    for (;;) {
      let length = 64 * 1024;
      if (opts.maxBytes !== undefined && Number.isFinite(opts.maxBytes)) {
        // Read one extra byte to detect growth without buffering the whole file.
        length = Math.min(length, Math.floor(opts.maxBytes) - total + 1);
      }
      const chunk = Buffer.alloc(length);
      const { bytesRead } = await handle.read(chunk, 0, length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      enforceCap(total, opts.maxBytes);
      chunks.push(chunk.subarray(0, bytesRead));
    }

    return makeBufferInput(
      Buffer.concat(chunks, total),
      opts.filename ?? path.basename(filePath),
      opts.declaredMime,
    );
  } finally {
    await handle.close();
  }
}

async function drainNodeReadable(stream: Readable, maxBytes?: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;

  try {
    for await (const chunk of stream) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array | string);
      total += buf.length;
      if (maxBytes !== undefined && total > maxBytes) {
        stream.destroy();
        throw new InputTooLargeError(total, maxBytes);
      }
      chunks.push(buf);
    }
  } catch (err) {
    if (err instanceof InputTooLargeError) throw err;
    throw new FileBouncerError("Failed to read Node Readable input", { cause: err });
  }

  return Buffer.concat(chunks, total);
}

async function drainWebStream(
  stream: ReadableStream<Uint8Array>,
  maxBytes?: number,
): Promise<Buffer> {
  const reader = stream.getReader();
  const chunks: Buffer[] = [];
  let total = 0;

  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!value) continue;
      const buf = Buffer.from(value);
      total += buf.length;
      if (maxBytes !== undefined && total > maxBytes) {
        await reader.cancel();
        throw new InputTooLargeError(total, maxBytes);
      }
      chunks.push(buf);
    }
  } catch (err) {
    if (err instanceof InputTooLargeError) throw err;
    throw new FileBouncerError("Failed to read ReadableStream input", { cause: err });
  } finally {
    reader.releaseLock();
  }

  return Buffer.concat(chunks, total);
}

function enforceCap(size: number, maxBytes: number | undefined): void {
  if (maxBytes !== undefined && size > maxBytes) {
    throw new InputTooLargeError(size, maxBytes);
  }
}

function isPathInput(x: unknown): x is { path: string } {
  if (x === null || typeof x !== "object") return false;
  const candidate = x as { path?: unknown };
  return typeof candidate.path === "string";
}

function hasName(blob: Blob): blob is Blob & { name: string } {
  return "name" in blob && typeof (blob as { name?: unknown }).name === "string";
}

function describe(x: unknown): string {
  if (x === null) return "null";
  if (Array.isArray(x)) return "Array";
  const t = typeof x;
  if (t !== "object") return t;
  const ctor = (x as { constructor?: { name?: string } }).constructor?.name;
  return ctor ?? "object";
}

/**
 * Extract a lowercased file extension (without leading dot) from a filename.
 * Returns `undefined` for hidden dotfiles, no extension, or trailing-dot names.
 */
export function parseExtension(filename: string | undefined): string | undefined {
  if (filename === undefined) return undefined;
  const base = filename.split(/[/\\]/).pop() ?? filename;
  const dot = base.lastIndexOf(".");
  if (dot <= 0 || dot === base.length - 1) return undefined;
  return base.slice(dot + 1).toLowerCase();
}
