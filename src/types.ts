/**
 * Public type surface for filebouncer.
 *
 * These types are part of the package's stable API. Adding fields is
 * non-breaking; renaming or removing them is breaking.
 */

/**
 * Severity ladder for individual threats. The engine compares findings
 * against `EngineConfig.blockThreshold` to decide whether `ScanResult.ok`
 * is `true` or `false`.
 */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** Coarse bucket derived from the highest-severity threat in a scan. */
export type Verdict = "clean" | "suspicious" | "malicious";

/**
 * A single detection emitted by a scanner. Threats are *findings*, not
 * errors — a scanner that runs successfully and finds nothing returns `[]`.
 */
export interface Threat {
  /** Name of the scanner that produced the finding (e.g. `"archive"`). */
  scanner: string;
  /** Stable machine-readable identifier (e.g. `"UNSAFE_ENTRY_PATH"`). */
  code: string;
  severity: Severity;
  /** Human-readable description of the finding. */
  message: string;
  /** Optional sub-path inside the file (e.g. archive entry name). */
  path?: string;
  /** Scanner-specific structured detail. */
  meta?: Record<string, unknown>;
}

/**
 * A non-fatal scanner failure. Modeled separately from {@link Threat} so
 * callers can distinguish "we found something bad" from "we couldn't
 * finish looking" — mirrors ClamAV's separation of `FOUND` vs `ERROR`.
 */
export interface ScanError {
  scanner: string;
  /** Stable identifier (e.g. `"SCAN_TIMEOUT"`, `"CORRUPT_ARCHIVE"`). */
  code: string;
  message: string;
  /** Original error, if any. */
  cause?: unknown;
}

/** A scanner that was not run, with the reason. */
export interface SkippedScanner {
  name: string;
  reason: string;
}

/**
 * Result of scanning a single file. Always returned (never thrown) for
 * detection or scan-error outcomes. Programmer errors (bad config,
 * unsupported input) throw a {@link FileBouncerError}.
 */
export interface ScanResult {
  /**
   * `true` iff no threat met or exceeded `EngineConfig.blockThreshold`
   * and no fatal error occurred. This is the boolean callers branch on.
   */
  ok: boolean;
  verdict: Verdict;
  filename?: string;
  /** Size of the input in bytes. */
  size: number;
  /** MIME inferred from magic bytes. */
  detectedMime?: string;
  /** MIME claimed by the caller (e.g. multipart `Content-Type`). */
  declaredMime?: string;
  /** Extension parsed from `filename`, lowercased, without leading dot. */
  extension?: string;
  threats: Threat[];
  errors: ScanError[];
  scannersRun: string[];
  scannersSkipped: SkippedScanner[];
  /** Total wall-clock time spent inside `engine.scan()`, in milliseconds. */
  durationMs: number;
  /** `true` if the scan was cut short by `timeoutMs`. */
  timedOut?: boolean;
}

/**
 * Per-call options passed alongside the input buffer.
 */
export interface ScanOptions {
  /** Original filename, used for extension parsing and MIME comparison. */
  filename?: string;
  /** MIME type claimed by the caller (e.g. multipart `Content-Type`). */
  declaredMime?: string;
}

/**
 * Context handed to each {@link Scanner}. Buffer-first: `read()` returns
 * the full input, memoized across scanners in the same scan call.
 */
export interface ScannerContext {
  filename?: string;
  declaredMime?: string;
  detectedMime?: string;
  /** Lowercased extension from magic bytes, if detected. */
  detectedExt?: string;
  /** Lowercased extension without leading dot, if derivable from `filename`. */
  extension?: string;
  /** Size of the input in bytes. */
  size: number;
  /** Returns the full input buffer. Memoized; safe to call repeatedly. */
  read(): Promise<Buffer>;
  /** Read-only view of the engine config, for scanner-specific options. */
  readonly config: Readonly<EngineConfig>;
}

/**
 * Pluggable detection module. Built-in scanners and user-supplied
 * scanners both implement this interface.
 */
export interface Scanner {
  /** Stable name used in `EngineConfig.scanners` and threat reports. */
  name: string;
  /**
   * Cheap predicate gating `scan()`. Returning `false` records the
   * scanner in `ScanResult.scannersSkipped` instead of running it.
   * Should not perform I/O.
   */
  appliesTo(ctx: ScannerContext): boolean;
  /**
   * Inspect the input and return any findings. Must not throw for
   * malformed input — return a {@link ScanError} via rejection only for
   * unrecoverable failures (timeouts, OOM); the engine converts thrown
   * errors into `ScanError` entries automatically.
   */
  scan(ctx: ScannerContext): Promise<Threat[]>;
}

/** Built-in scanner identifiers selectable via `EngineConfig.scanners`. */
export type BuiltInScannerName = "mime" | "metadata" | "csv" | "archive" | "polyglot";

export interface ArchiveConfig {
  /** Maximum number of entries before flagging a bomb. */
  maxEntries?: number;
  /** Maximum total uncompressed size, in bytes. */
  maxTotalUncompressed?: number;
  /** Maximum uncompressed:compressed ratio per entry and aggregate. */
  maxRatio?: number;
  /** Maximum recursion depth for nested archives. `0` disables recursion. */
  maxDepth?: number;
  /** Whether to permit symlink entries. */
  allowSymlinks?: boolean;
}

export interface CsvConfig {
  /** Cell prefixes that trigger unsafe-cell findings. */
  prefixes?: string[];
  /** Stop scanning after N rows (0 = unlimited). */
  maxRows?: number;
  /** Field delimiter; auto-detected if omitted. */
  delimiter?: string;
}

export interface MimeConfig {
  /** If set, only these MIME types are accepted (others become threats). */
  allowList?: string[];
  /** MIME types that always become threats. */
  denyList?: string[];
  /** Treat MIME mismatches as `critical` instead of `medium`. */
  strict?: boolean;
}

export interface MetadataConfig {
  /** Lowercased extensions (without dot) that always become threats. Merged with built-in defaults. */
  denyExtensions?: string[];
  /** Permit multiple dotted extensions such as `.tar.gz`. Defaults to `false`. */
  allowDoubleExtension?: boolean;
}

export interface PolyglotConfig {
  /**
   * Ignore secondary format hits whose byte offset is below this value.
   * Defaults to `0`.
   */
  minSecondaryOffset?: number;
  /**
   * Maximum number of leading bytes to inspect for secondary signatures.
   * Defaults to the full buffer.
   */
  maxScanBytes?: number;
  /**
   * Allowed trailing bytes after a complete JPEG/PNG before flagging
   * unexplained trailing content. Defaults to `32`.
   */
  trailingTolerance?: number;
}

export interface EngineConfig {
  /** Built-in scanners to enable. `"all"` enables every shipped scanner. */
  scanners?: BuiltInScannerName[] | "all";
  /** User-supplied scanners, run alongside the built-ins. */
  customScanners?: Scanner[];
  /** Hard upper bound on input size, in bytes. Larger inputs are rejected. */
  maxFileSize?: number;
  /**
   * Threats with severity >= this value flip `ScanResult.ok` to `false`.
   * Defaults to `"high"`.
   */
  blockThreshold?: Severity;
  /** Stop the pipeline at the first `critical` finding. */
  failFast?: boolean;
  /** Overall scan budget in milliseconds. */
  timeoutMs?: number;
  archive?: ArchiveConfig;
  csv?: CsvConfig;
  mime?: MimeConfig;
  metadata?: MetadataConfig;
  polyglot?: PolyglotConfig;
}

/**
 * Thrown only on programmer errors: invalid config, unsupported input
 * type, or impossible state. Detections and scan failures are returned
 * as data on {@link ScanResult}.
 */
export class FileBouncerError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "FileBouncerError";
  }
}
