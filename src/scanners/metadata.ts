import type { MetadataConfig, Scanner, ScannerContext, Severity, Threat } from "../types";

const DEFAULT_DENY_EXTENSIONS = [
  "exe",
  "scr",
  "bat",
  "cmd",
  "com",
  "pif",
  "msi",
  "vbs",
  "js",
  "jse",
  "wsh",
  "ps1",
  "dll",
  "reg",
  "inf",
];

const DOCUMENT_EXTENSIONS = new Set([
  "pdf",
  "doc",
  "docx",
  "xls",
  "xlsx",
  "ppt",
  "pptx",
  "txt",
  "csv",
  "jpg",
  "jpeg",
  "png",
  "gif",
]);

const EXECUTABLE_EXTENSIONS = new Set([
  "exe",
  "scr",
  "bat",
  "cmd",
  "com",
  "pif",
  "msi",
  "vbs",
  "js",
  "jse",
  "wsh",
  "ps1",
  "dll",
]);

export class MetadataScanner implements Scanner {
  readonly name = "metadata";

  private readonly denyExtensions: Set<string>;

  constructor(private readonly config: MetadataConfig = {}) {
    this.denyExtensions = new Set([
      ...DEFAULT_DENY_EXTENSIONS,
      ...(config.denyExtensions ?? []).map((ext) => ext.toLowerCase()),
    ]);
  }

  appliesTo(ctx: ScannerContext): boolean {
    return ctx.filename !== undefined;
  }

  scan(ctx: ScannerContext): Promise<Threat[]> {
    const threats: Threat[] = [];
    const filename = ctx.filename;
    if (!filename) return Promise.resolve(threats);

    this.checkUnsafeFilename(filename, threats);
    this.checkNullByteFilename(filename, threats);

    const segments = MetadataScanner.parseExtensionSegments(filename);
    if (segments.length === 0) return Promise.resolve(threats);

    this.checkDoubleExtension(segments, threats);
    this.checkSuspiciousExtension(segments, threats);
    this.checkExecutableDisguised(segments, threats);

    return Promise.resolve(threats);
  }

  private static basename(filename: string) {
    return filename.split(/[/\\]/).pop() ?? filename;
  }

  private static parseExtensionSegments(filename: string) {
    const base = MetadataScanner.basename(filename);
    const dot = base.indexOf(".");
    if (dot <= 0) return [];

    return base
      .slice(dot + 1)
      .split(".")
      .map((segment) => segment.toLowerCase())
      .filter((segment) => segment.length > 0);
  }

  private checkUnsafeFilename(filename: string, threats: Threat[]) {
    if (filename.includes("..") || filename.includes("/") || filename.includes("\\")) {
      this.pushThreat(
        threats,
        "UNSAFE_FILENAME",
        "high",
        `Filename contains unsafe path characters: ${filename}`,
        filename,
      );
    }
  }

  private checkNullByteFilename(filename: string, threats: Threat[]) {
    if (!filename.includes("\0")) return;

    this.pushThreat(
      threats,
      "NULL_BYTE_FILENAME",
      "critical",
      "Filename contains a null byte",
      filename,
    );
  }

  private checkDoubleExtension(segments: string[], threats: Threat[]) {
    if (this.config.allowDoubleExtension || segments.length <= 1) return;

    this.pushThreat(
      threats,
      "DOUBLE_EXTENSION",
      "medium",
      `Filename has multiple extensions: .${segments.join(".")}`,
      undefined,
      { extensions: segments },
    );
  }

  private checkSuspiciousExtension(segments: string[], threats: Threat[]) {
    const flagged = segments.filter((segment) => this.denyExtensions.has(segment));
    if (flagged.length === 0) return;

    this.pushThreat(
      threats,
      "SUSPICIOUS_EXTENSION",
      "high",
      `Filename uses suspicious extension(s): .${flagged.join(", .")}`,
      undefined,
      { extensions: flagged },
    );
  }

  private checkExecutableDisguised(segments: string[], threats: Threat[]) {
    if (segments.length < 2) return;

    const finalExt = segments[segments.length - 1]!;
    if (!EXECUTABLE_EXTENSIONS.has(finalExt)) return;

    const innerExtensions = segments.slice(0, -1);
    const disguised = innerExtensions.some((segment) => DOCUMENT_EXTENSIONS.has(segment));
    if (!disguised) return;

    this.pushThreat(
      threats,
      "EXECUTABLE_DISGUISED",
      "critical",
      `Executable extension ".${finalExt}" hidden behind document-like name ".${innerExtensions.join(".")}.${finalExt}"`,
      undefined,
      { extensions: segments },
    );
  }

  private pushThreat(
    threats: Threat[],
    code: string,
    severity: Severity,
    message: string,
    filename: string | undefined,
    meta?: Record<string, unknown>,
  ) {
    threats.push({
      scanner: this.name,
      code,
      severity,
      message,
      meta: filename === undefined ? meta : { filename, ...meta },
    });
  }
}
