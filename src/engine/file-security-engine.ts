import { resolveBuiltInScanners } from "./built-ins";
import { type RawInput, InputTooLargeError, normalizeInput } from "../input";
import { detectType } from "../util/detect-type";
import type {
  EngineConfig,
  ScanError,
  ScanOptions,
  ScanResult,
  Scanner,
  ScannerContext,
  SkippedScanner,
  Threat,
} from "../types";
import { computeVerdict, meetsThreshold } from "./verdict";

/** Default upload size cap when `EngineConfig.maxFileSize` is omitted (50 MiB). */
export const DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024;

export class FileSecurityEngine {
  private readonly config: EngineConfig;
  private readonly scanners: Scanner[];

  constructor(config: EngineConfig = {}) {
    this.config = config;
    this.scanners = [...resolveBuiltInScanners(config), ...(config.customScanners ?? [])];
  }

  use(scanner: Scanner) {
    this.scanners.push(scanner);
  }

  async scan(input: RawInput, opts?: ScanOptions): Promise<ScanResult> {
    const startTime = Date.now();
    const { timeoutMs, failFast } = this.config;

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
    let timedOut = false;

    for (let i = 0; i < this.scanners.length; i++) {
      const scanner = this.scanners[i]!;

      if (timeoutMs && Date.now() - startTime >= timeoutMs) {
        timedOut = true;
        for (let j = i; j < this.scanners.length; j++) {
          scannersSkipped.push({ name: this.scanners[j]!.name, reason: "timeout" });
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
        threats.push(...findings);
      } catch (err) {
        errors.push({
          scanner: scanner.name,
          code: "SCANNER_ERROR",
          message: err instanceof Error ? err.message : "Unknown scanner error",
          cause: err,
        });
      }

      if (failFast && threats.some((t) => t.severity === "critical")) {
        for (let j = i + 1; j < this.scanners.length; j++) {
          scannersSkipped.push({ name: this.scanners[j]!.name, reason: "fail-fast" });
        }
        break;
      }
    }

    const blockThreshold = this.config.blockThreshold ?? "high";
    const isBlocked = threats.some((t) => meetsThreshold(t.severity, blockThreshold));
    const hasScanFailure = errors.length > 0 || timedOut;
    const verdict = computeVerdict(threats);

    return {
      ok: !isBlocked && !hasScanFailure,
      verdict,
      filename: normalized.filename,
      size: normalized.size,
      detectedMime: detected?.mime,
      declaredMime: normalized.declaredMime,
      extension: normalized.extension,
      threats,
      errors,
      scannersRun,
      scannersSkipped,
      durationMs: Date.now() - startTime,
      timedOut,
    };
  }
}
