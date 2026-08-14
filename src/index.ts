export type {
  ArchiveConfig,
  BuiltInScannerName,
  CsvConfig,
  EngineConfig,
  MetadataConfig,
  MimeConfig,
  PolyglotConfig,
  ScanError,
  ScanOptions,
  ScanResult,
  Scanner,
  ScannerContext,
  Severity,
  SkippedScanner,
  Threat,
  Verdict,
} from "./types";

export { FileBouncerError } from "./types";

export type { NormalizeOptions, NormalizedInput, RawInput } from "./input";

export { InputTooLargeError, normalizeInput, parseExtension } from "./input";

export type { DetectedType } from "./util/detect-type";

export { detectType } from "./util/detect-type";

export { DEFAULT_MAX_FILE_SIZE, FileSecurityEngine, scanBuffer } from "./engine";

export {
  ArchiveScanner,
  CsvScanner,
  MetadataScanner,
  MimeScanner,
  PolyglotScanner,
} from "./scanners";
