import { MetadataScanner } from "../scanners/metadata";
import { MimeScanner } from "../scanners/mime";
import type { EngineConfig, Scanner } from "../types";

export const resolveBuiltInScanners = (config: EngineConfig): Scanner[] => {
  const selected = config.scanners;
  if (!selected) return [];

  const scanners: Scanner[] = [];

  if (selected === "all" || selected.includes("mime")) {
    scanners.push(new MimeScanner(config.mime));
  }

  if (selected === "all" || selected.includes("metadata")) {
    scanners.push(new MetadataScanner(config.metadata));
  }

  return scanners;
};
