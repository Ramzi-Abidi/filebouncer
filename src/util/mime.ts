/** Strip parameters (`; charset=...`) and lowercase a MIME type. */
export const normalizeMime = (mime: string): string => mime.split(";")[0]!.trim().toLowerCase();

/**
 * Non-standard or legacy MIME spellings that browsers and operating systems
 * send for the same format, mapped to the spelling `file-type` reports.
 * Without this, e.g. a normal ZIP uploaded from Windows (`application/x-zip-compressed`)
 * looks like a declared/detected mismatch.
 */
const MIME_ALIASES: Readonly<Record<string, string>> = {
  "image/jpg": "image/jpeg",
  "image/pjpeg": "image/jpeg",
  "image/x-png": "image/png",
  "image/x-ms-bmp": "image/bmp",
  "image/x-bmp": "image/bmp",
  "image/vnd.microsoft.icon": "image/x-icon",
  "application/x-zip-compressed": "application/zip",
  "application/x-zip": "application/zip",
  "multipart/x-zip": "application/zip",
  "application/x-pdf": "application/pdf",
  "application/x-gzip": "application/gzip",
  "text/rtf": "application/rtf",
  "audio/x-wav": "audio/wav",
  "audio/wave": "audio/wav",
  "audio/vnd.wave": "audio/wav",
  "audio/mp3": "audio/mpeg",
  "audio/mid": "audio/midi",
  "audio/x-midi": "audio/midi",
  "audio/mp4": "audio/x-m4a",
  "audio/m4a": "audio/x-m4a",
  "video/x-msvideo": "video/vnd.avi",
  "video/avi": "video/vnd.avi",
  "video/msvideo": "video/vnd.avi",
  "application/csv": "text/csv",
  "text/comma-separated-values": "text/csv",
  "text/x-csv": "text/csv",
};

/** Normalized MIME with known aliases collapsed to one canonical spelling. */
export const canonicalMime = (mime: string): string => {
  const normalized = normalizeMime(mime);
  return MIME_ALIASES[normalized] ?? normalized;
};

/**
 * Declared types that mean "I don't know" rather than a claim about the
 * content. Browsers send these for unfamiliar extensions, so they must not
 * be treated as a mismatch.
 */
const GENERIC_MIMES = new Set([
  "application/octet-stream",
  "binary/octet-stream",
  "application/unknown",
  "application/x-unknown",
]);

export const isGenericMime = (mime: string): boolean => GENERIC_MIMES.has(normalizeMime(mime));

/**
 * `file-type` reports every legacy Office file (.doc/.xls/.ppt/.msg, ...) as
 * the generic container `application/x-cfb` / `cfb`. These are the claims a
 * CFB file can legitimately satisfy. MSI installers share the container but
 * are re-labelled by `detectType`, so they never reach this list.
 */
export const CFB_MIME = "application/x-cfb";
export const CFB_EXT = "cfb";

const LEGACY_OFFICE_MIMES = new Set([
  "application/msword",
  "application/vnd.ms-excel",
  "application/vnd.ms-powerpoint",
  "application/vnd.ms-outlook",
  "application/vnd.visio",
  "application/vnd.ms-visio.drawing",
  "application/x-mspublisher",
  "application/vnd.ms-publisher",
]);

export const LEGACY_OFFICE_EXTENSIONS = new Set([
  "doc",
  "dot",
  "xls",
  "xlt",
  "ppt",
  "pot",
  "pps",
  "msg",
  "vsd",
  "pub",
]);

/** Whether content detected as `detected` satisfies a claimed MIME type. */
export const mimeSatisfies = (claimed: string, detected: string): boolean => {
  const claimedCanonical = canonicalMime(claimed);
  const detectedCanonical = canonicalMime(detected);
  if (claimedCanonical === detectedCanonical) return true;
  return detectedCanonical === CFB_MIME && LEGACY_OFFICE_MIMES.has(claimedCanonical);
};
