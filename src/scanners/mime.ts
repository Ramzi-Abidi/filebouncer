import type { MimeConfig, Scanner, ScannerContext, Severity, Threat } from "../types";
import {
  CFB_EXT,
  LEGACY_OFFICE_EXTENSIONS,
  canonicalMime,
  isGenericMime,
  mimeSatisfies,
} from "../util/mime";
import { inferTextMime } from "../util/text-type";

const mismatchSeverity = (strict?: boolean): Severity => (strict ? "critical" : "medium");

const EXTENSION_ALIASES = [
  new Set(["jpg", "jpeg", "jpe", "jfif"]),
  new Set(["tif", "tiff"]),
  new Set(["heic", "heif"]),
  new Set(["mid", "midi"]),
  new Set(["gz", "tgz"]),
];

const extensionsMatch = (extension: string, detectedExt: string): boolean =>
  extension === detectedExt ||
  EXTENSION_ALIASES.some((aliases) => aliases.has(extension) && aliases.has(detectedExt)) ||
  (detectedExt === CFB_EXT && LEGACY_OFFICE_EXTENSIONS.has(extension));

export class MimeScanner implements Scanner {
  readonly name = "mime";

  constructor(private readonly config: MimeConfig = {}) {}

  appliesTo(ctx: ScannerContext) {
    if (this.config.allowList?.length || this.config.denyList?.length) return true;
    if (ctx.extension || ctx.declaredMime) return true;
    return false;
  }

  async scan(ctx: ScannerContext) {
    const threats: Threat[] = [];

    this.checkDenyList(ctx, threats);
    await this.checkAllowList(ctx, threats);
    this.checkExtensionMismatch(ctx, threats);
    this.checkDeclaredMimeMismatch(ctx, threats);

    return threats;
  }

  private checkDenyList(ctx: ScannerContext, threats: Threat[]) {
    const { detectedMime } = ctx;
    if (!detectedMime) return;

    const denied = this.config.denyList?.some(
      (m) => canonicalMime(m) === canonicalMime(detectedMime),
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

  private async checkAllowList(ctx: ScannerContext, threats: Threat[]) {
    const { allowList } = this.config;
    if (!allowList?.length) return;

    // Text formats (CSV, TXT, JSON...) have no signature; fall back to
    // verifying the bytes are genuine text matching the filename extension.
    const effectiveMime = ctx.detectedMime ?? inferTextMime(await ctx.read(), ctx.extension);
    const allowed =
      effectiveMime !== undefined && allowList.some((m) => mimeSatisfies(m, effectiveMime));

    if (allowed) return;

    this.pushThreat(
      threats,
      "MIME_NOT_ALLOWED",
      "high",
      effectiveMime === undefined
        ? "File type could not be detected and is not on the allow list"
        : `Detected MIME type ${effectiveMime} is not on the allow list`,
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
    if (isGenericMime(declaredMime) || mimeSatisfies(declaredMime, detectedMime)) return;

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
