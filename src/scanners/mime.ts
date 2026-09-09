import type { MimeConfig, Scanner, ScannerContext, Severity, Threat } from "../types";

const normalizeMime = (mime: string): string => mime.split(";")[0]!.trim().toLowerCase();

const mismatchSeverity = (strict?: boolean): Severity => (strict ? "critical" : "medium");

const EXTENSION_ALIASES = [new Set(["jpg", "jpeg"]), new Set(["tif", "tiff"])];

const extensionsMatch = (extension: string, detectedExt: string): boolean =>
  extension === detectedExt ||
  EXTENSION_ALIASES.some((aliases) => aliases.has(extension) && aliases.has(detectedExt));

export class MimeScanner implements Scanner {
  readonly name = "mime";

  constructor(private readonly config: MimeConfig = {}) {}

  appliesTo(ctx: ScannerContext) {
    if (this.config.allowList?.length || this.config.denyList?.length) return true;
    if (ctx.extension || ctx.declaredMime) return true;
    return false;
  }

  scan(ctx: ScannerContext) {
    const threats: Threat[] = [];

    this.checkDenyList(ctx, threats);
    this.checkAllowList(ctx, threats);
    this.checkExtensionMismatch(ctx, threats);
    this.checkDeclaredMimeMismatch(ctx, threats);

    return Promise.resolve(threats);
  }

  private checkDenyList(ctx: ScannerContext, threats: Threat[]) {
    const { detectedMime } = ctx;
    if (!detectedMime) return;

    const denied = this.config.denyList?.some(
      (m) => normalizeMime(m) === normalizeMime(detectedMime),
    );
    if (!denied) return;

    this.pushThreat(
      threats,
      "MIME_DENIED",
      "high",
      `Detected MIME type ${detectedMime} is denied`,
      ctx,
    );
  }

  private checkAllowList(ctx: ScannerContext, threats: Threat[]) {
    if (!this.config.allowList?.length) return;

    const { detectedMime } = ctx;
    const allowed =
      detectedMime !== undefined &&
      this.config.allowList.some((m) => normalizeMime(m) === normalizeMime(detectedMime));

    if (allowed) return;

    this.pushThreat(
      threats,
      "MIME_NOT_ALLOWED",
      "high",
      detectedMime === undefined
        ? "File type could not be detected and is not on the allow list"
        : `Detected MIME type ${detectedMime} is not on the allow list`,
      ctx,
    );
  }

  private checkExtensionMismatch(ctx: ScannerContext, threats: Threat[]) {
    const { extension, detectedExt } = ctx;
    if (!extension || !detectedExt || extensionsMatch(extension, detectedExt)) return;

    this.pushThreat(
      threats,
      "EXTENSION_MISMATCH",
      mismatchSeverity(this.config.strict),
      `Filename extension ".${extension}" does not match detected type ".${detectedExt}"`,
      ctx,
    );
  }

  private checkDeclaredMimeMismatch(ctx: ScannerContext, threats: Threat[]) {
    const { declaredMime, detectedMime } = ctx;
    if (!declaredMime || !detectedMime) return;
    if (normalizeMime(declaredMime) === normalizeMime(detectedMime)) return;

    this.pushThreat(
      threats,
      "DECLARED_MIME_MISMATCH",
      mismatchSeverity(this.config.strict),
      `Declared MIME type ${declaredMime} does not match detected type ${detectedMime}`,
      ctx,
    );
  }

  private pushThreat(
    threats: Threat[],
    code: string,
    severity: Severity,
    message: string,
    ctx: ScannerContext,
  ): void {
    threats.push({
      scanner: this.name,
      code,
      severity,
      message,
      meta: this.buildMeta(ctx),
    });
  }

  private buildMeta(ctx: ScannerContext): Record<string, unknown> {
    return {
      claimedExtension: ctx.extension,
      detectedExt: ctx.detectedExt,
      declaredMime: ctx.declaredMime,
      detectedMime: ctx.detectedMime,
    };
  }
}
