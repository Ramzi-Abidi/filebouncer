import { BUILT_IN_SCANNERS, resolveBuiltInScanners } from "./built-ins";
import { ScanFailureError } from "./scan-failure-error";
import { type RawInput, InputTooLargeError, normalizeInput } from "../input";
import { detectType } from "../util/detect-type";
import { FileBouncerError } from "../types";
import type {
  EngineConfig,
  ScanError,
  ScanOptions,
  ScanResult,
  Scanner,
  ScannerContext,
  Severity,
  SkippedScanner,
  Threat,
} from "../types";
import { computeVerdict, meetsThreshold, moreSevere, SEVERITY_ORDER } from "./verdict";

export const DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB
const DEFAULT_MAX_FINDINGS = 100;

export class FileSecurityEngine {
  private readonly config: EngineConfig;
  private readonly scanners: Scanner[];
  private readonly maxFindings: number;

  constructor(config: EngineConfig = {}) {
    const {
      maxFileSize,
      timeoutMs,
      maxFindings = DEFAULT_MAX_FINDINGS,
      blockThreshold,
      scanners,
    } = config;

    if (maxFileSize !== undefined && (!Number.isFinite(maxFileSize) || maxFileSize < 0)) {
      throw new FileBouncerError("maxFileSize must be a non-negative finite number");
    }
    if (timeoutMs !== undefined && (!Number.isFinite(timeoutMs) || timeoutMs < 0)) {
      throw new FileBouncerError("timeoutMs must be a non-negative finite number");
    }
    if (!Number.isInteger(maxFindings) || maxFindings <= 0) {
      throw new FileBouncerError("maxFindings must be a positive integer");
    }
    if (
      blockThreshold !== undefined &&
      !(SEVERITY_ORDER as readonly string[]).includes(blockThreshold)
    ) {
      throw new FileBouncerError(`Invalid blockThreshold: ${String(blockThreshold)}`);
    }
    if (scanners !== undefined && scanners !== "all") {
      if (!Array.isArray(scanners)) {
        throw new FileBouncerError("scanners must be 'all' or an array of scanner names");
      }
      for (const name of scanners) {
        if (!(BUILT_IN_SCANNERS as readonly string[]).includes(name)) {
          throw new FileBouncerError(`Unknown built-in scanner name: ${String(name)}`);
        }
      }
    }

    if (
      config.csv?.maxRows !== undefined &&
      (!Number.isInteger(config.csv.maxRows) || config.csv.maxRows < 0)
    ) {
      throw new FileBouncerError("csv.maxRows must be a non-negative integer");
    }

    if (config.archive) {
      const { maxEntries, maxTotalUncompressed, maxRatio, maxDepth } = config.archive;
      if (maxEntries !== undefined && (!Number.isInteger(maxEntries) || maxEntries < 0)) {
        throw new FileBouncerError("archive.maxEntries must be a non-negative integer");
      }
      if (
        maxTotalUncompressed !== undefined &&
        (!Number.isFinite(maxTotalUncompressed) || maxTotalUncompressed < 0)
      ) {
        throw new FileBouncerError(
          "archive.maxTotalUncompressed must be a non-negative finite number",
        );
      }
      if (maxRatio !== undefined && (!Number.isFinite(maxRatio) || maxRatio < 0)) {
        throw new FileBouncerError("archive.maxRatio must be a non-negative finite number");
      }
      if (maxDepth !== undefined && (!Number.isInteger(maxDepth) || maxDepth < 0)) {
        throw new FileBouncerError("archive.maxDepth must be a non-negative integer");
      }
    }

    if (config.polyglot) {
      const { minSecondaryOffset, maxScanBytes, trailingTolerance } = config.polyglot;
      if (
        minSecondaryOffset !== undefined &&
        (!Number.isInteger(minSecondaryOffset) || minSecondaryOffset < 0)
      ) {
        throw new FileBouncerError("polyglot.minSecondaryOffset must be a non-negative integer");
      }
      if (maxScanBytes !== undefined && (!Number.isInteger(maxScanBytes) || maxScanBytes < 0)) {
        throw new FileBouncerError("polyglot.maxScanBytes must be a non-negative integer");
      }
      if (
        trailingTolerance !== undefined &&
        (!Number.isInteger(trailingTolerance) || trailingTolerance < 0)
      ) {
        throw new FileBouncerError("polyglot.trailingTolerance must be a non-negative integer");
      }
    }

    this.config = Object.freeze({
      ...config,

      scanners: Array.isArray(config.scanners) ? [...config.scanners] : config.scanners,

      customScanners: config.customScanners ? [...config.customScanners] : undefined,

      csv: config.csv
        ? {
            ...config.csv,
            prefixes: config.csv.prefixes ? [...config.csv.prefixes] : undefined,
          }
        : undefined,

      mime: config.mime
        ? {
            ...config.mime,
            allowList: config.mime.allowList ? [...config.mime.allowList] : undefined,
            denyList: config.mime.denyList ? [...config.mime.denyList] : undefined,
          }
        : undefined,

      metadata: config.metadata
        ? {
            ...config.metadata,
            denyExtensions: config.metadata.denyExtensions
              ? [...config.metadata.denyExtensions]
              : undefined,
          }
        : undefined,

      archive: config.archive ? { ...config.archive } : undefined,
      polyglot: config.polyglot ? { ...config.polyglot } : undefined,
    });

    this.scanners = [...resolveBuiltInScanners(this.config), ...(this.config.customScanners ?? [])];
    this.maxFindings = maxFindings;
  }

  use(scanner: Scanner) {
    this.scanners.push(scanner);
  }

  async scan(input: RawInput, opts?: ScanOptions): Promise<ScanResult> {
    const startTime = Date.now();
    const { timeoutMs, failFast } = this.config;
    const scanners = [...this.scanners];

    let normalized;
    try {
      normalized = await normalizeInput(input, {
        filename: opts?.filename,
        declaredMime: opts?.declaredMime,
        maxBytes: this.config.maxFileSize ?? DEFAULT_MAX_FILE_SIZE,
      });
    } catch (err) {
      if (err instanceof InputTooLargeError) {
        return {
          ok: false,
          outcome: "blocked",
          verdict: "malicious",
          size: err.observedAtLeast,
          threats: [
            {
              scanner: "engine",
              code: "FILE_TOO_LARGE",
              severity: "critical",
              message: `File exceeds maximum allowed size of ${String(err.maxBytes)} bytes`,
            },
          ],
          errors: [],
          scannersRun: [],
          scannersSkipped: [],
          durationMs: Date.now() - startTime,
        };
      }
      throw err;
    }

    const buffer = await normalized.read();
    const detected = await detectType(buffer);

    const ctx: ScannerContext = {
      filename: normalized.filename,
      declaredMime: normalized.declaredMime,
      detectedMime: detected?.mime,
      detectedExt: detected?.ext,
      extension: normalized.extension,
      size: normalized.size,
      read: () => normalized.read(),
      config: this.config,
    };

    const threats: Threat[] = [];
    const errors: ScanError[] = [];
    const scannersRun: string[] = [];
    const scannersSkipped: SkippedScanner[] = [];
    const blockThreshold = this.config.blockThreshold ?? "high";
    let totalFindings = 0;
    let worstSeverity: Severity | undefined;
    let isBlocked = false;
    let hasCriticalFinding = false;
    let timedOut = false;

    for (let i = 0; i < scanners.length; i++) {
      const scanner = scanners[i]!;

      if (timeoutMs && Date.now() - startTime >= timeoutMs) {
        timedOut = true;
        for (let j = i; j < scanners.length; j++) {
          scannersSkipped.push({ name: scanners[j]!.name, reason: "timeout" });
        }
        errors.push({
          scanner: "engine",
          code: "SCAN_TIMEOUT",
          message: `Scan budget of ${String(timeoutMs)}ms exceeded`,
        });
        break;
      }

      if (!scanner.appliesTo(ctx)) {
        scannersSkipped.push({ name: scanner.name, reason: "appliesTo returned false" });
        continue;
      }

      scannersRun.push(scanner.name);

      try {
        const findings = await scanner.scan(ctx);
        for (const finding of findings) {
          totalFindings += 1;
          worstSeverity = moreSevere(worstSeverity, finding.severity);
          isBlocked ||= meetsThreshold(finding.severity, blockThreshold);
          hasCriticalFinding ||= finding.severity === "critical";

          if (threats.length < this.maxFindings) {
            threats.push(finding);
          }
        }
      } catch (err) {
        errors.push({
          scanner: scanner.name,
          code: err instanceof ScanFailureError ? err.code : "SCANNER_ERROR",
          message: err instanceof Error ? err.message : "Unknown scanner error",
          cause: err,
        });
      }

      if (failFast && hasCriticalFinding) {
        for (let j = i + 1; j < scanners.length; j++) {
          scannersSkipped.push({ name: scanners[j]!.name, reason: "fail-fast" });
        }
        break;
      }
    }

    const hasScanFailure = errors.length > 0 || timedOut;
    const verdict = computeVerdict(worstSeverity);
    const outcome = hasScanFailure ? "incomplete" : isBlocked ? "blocked" : "pass";
    const findingsTruncated = totalFindings > threats.length;

    return {
      ok: !isBlocked && !hasScanFailure,
      outcome,
      verdict,
      filename: normalized.filename,
      size: normalized.size,
      detectedMime: detected?.mime,
      declaredMime: normalized.declaredMime,
      extension: normalized.extension,
      threats,
      ...(findingsTruncated ? { findingsTruncated: true, totalFindings } : {}),
      errors,
      scannersRun,
      scannersSkipped,
      durationMs: Date.now() - startTime,
      timedOut,
    };
  }
}
