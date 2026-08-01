import { ArchiveScanner } from "../scanners/archive";
import { CsvScanner } from "../scanners/csv";
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

  if (selected === "all" || selected.includes("csv")) {
    scanners.push(new CsvScanner(config.csv));
  }

  if (selected === "all" || selected.includes("archive")) {
    scanners.push(new ArchiveScanner(config.archive));
  }

  return scanners;
};
