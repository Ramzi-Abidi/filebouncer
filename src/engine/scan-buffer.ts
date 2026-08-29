import type { EngineConfig, ScanOptions, ScanResult } from "../types";
import { FileSecurityEngine } from "./file-security-engine";

/**
 * Scan a buffer with default config (all built-in scanners, no custom scanners).
 * For repeated use, create a FileSecurityEngine instance instead.
 */
export const scanBuffer = async (
  buffer: Buffer,
  opts?: ScanOptions & { config?: EngineConfig },
): Promise<ScanResult> => {
  const engine = new FileSecurityEngine(opts?.config);
  return engine.scan(buffer, opts);
};
