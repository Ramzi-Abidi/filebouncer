import type { Severity, Threat } from "../types";

const ARCHIVE_SCANNER_NAME = "archive";

export function makeArchiveThreat(
  code: string,
  severity: Severity,
  message: string,
  path: string | undefined,
  meta?: Record<string, unknown>,
): Threat {
  const threat: Threat = {
    scanner: ARCHIVE_SCANNER_NAME,
    code,
    severity,
    message,
  };
  if (path !== undefined) threat.path = path;
  if (meta !== undefined) threat.meta = meta;
  return threat;
}

export function checkArchiveEntryName(fileName: string, threats: Threat[]): void {
  if (fileName.includes("\0")) {
    threats.push(
      makeArchiveThreat(
        "UNSAFE_ENTRY_PATH",
        "critical",
        "Archive entry name contains a null byte",
        fileName,
      ),
    );
    return;
  }

  if (fileName.startsWith("/") || /^[A-Za-z]:[/\\]/.test(fileName)) {
    threats.push(
      makeArchiveThreat(
        "UNSAFE_ABS_PATH",
        "high",
        `Archive entry uses an absolute path: ${fileName}`,
        fileName,
      ),
    );
  }

  const segments = fileName.split(/[/\\]/);
  if (segments.some((segment) => segment === "..")) {
    threats.push(
      makeArchiveThreat(
        "UNSAFE_ENTRY_PATH",
        "critical",
        `Archive entry path leaves the destination directory: ${fileName}`,
        fileName,
      ),
    );
  }
}

export function checkArchiveSymlink(
  fileName: string,
  isSymlink: boolean,
  allowSymlinks: boolean,
  threats: Threat[],
): void {
  if (allowSymlinks || !isSymlink) return;

  threats.push(
    makeArchiveThreat("LINK_ENTRY", "high", `Archive contains a link entry: ${fileName}`, fileName),
  );
}
