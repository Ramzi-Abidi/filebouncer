/**
 * Plain-text formats have no magic bytes, so signature detection returns
 * nothing for them. For these extensions we instead confirm the bytes really
 * are text and report the MIME the extension implies.
 */
const TEXT_EXTENSION_MIMES: Readonly<Record<string, string>> = {
  csv: "text/csv",
  tsv: "text/tab-separated-values",
  txt: "text/plain",
  json: "application/json",
  md: "text/markdown",
};

/** Markup that browsers render or servers execute — never "plain text". */
const MARKUP_AT_START =
  /^\uFEFF?\s*<(?:!doctype|html|head|body|script|svg|iframe|object|embed|\?xml)\b/i;
const PHP_TAG = /<\?php/i;
const MARKUP_HEAD_CHARS = 1024;

/**
 * Returns the MIME implied by `extension` when the buffer is genuine text, or
 * `undefined` when the extension is not a text format, the content looks
 * binary, or the content is HTML/SVG/XML/PHP pretending to be text.
 *
 * Accepts UTF-8, legacy 8-bit encodings (e.g. Windows-1252 CSV exports from
 * Excel) and UTF-16 with a byte-order mark (Excel "Unicode Text").
 */
export function inferTextMime(buffer: Buffer, extension: string | undefined): string | undefined {
  if (extension === undefined) return undefined;
  const mime = TEXT_EXTENSION_MIMES[extension];
  if (mime === undefined || buffer.length === 0) return undefined;

  const text = decodeText(buffer);
  if (text === undefined) return undefined;
  if (MARKUP_AT_START.test(text.slice(0, MARKUP_HEAD_CHARS)) || PHP_TAG.test(text)) {
    return undefined;
  }
  return mime;
}

/**
 * True for UTF-16 text with a byte-order mark. Signature detection misreads
 * the little-endian BOM (`FF FE`) as an MPEG audio frame header, so callers
 * must check this before trusting a detected type.
 */
export function isUtf16Text(buffer: Buffer): boolean {
  const hasBom =
    (buffer[0] === 0xff && buffer[1] === 0xfe) || (buffer[0] === 0xfe && buffer[1] === 0xff);
  return hasBom && buffer.length > 2 && decodeText(buffer) !== undefined;
}

function decodeText(buffer: Buffer): string | undefined {
  let text: string;
  if (buffer[0] === 0xff && buffer[1] === 0xfe) {
    text = buffer.subarray(2).toString("utf16le");
  } else if (buffer[0] === 0xfe && buffer[1] === 0xff) {
    const body = Buffer.from(buffer.subarray(2, 2 + ((buffer.length - 2) & ~1)));
    text = body.swap16().toString("utf16le");
  } else {
    // Byte-level check first: no need to decode anything to reject binary data.
    for (const byte of buffer) {
      if (isBinaryControl(byte)) return undefined;
    }
    const hasUtf8Bom = buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf;
    return buffer.subarray(hasUtf8Bom ? 3 : 0).toString("latin1");
  }

  for (let i = 0; i < text.length; i++) {
    if (isBinaryControl(text.charCodeAt(i))) return undefined;
  }
  return text;
}

/**
 * C0 control characters that do not occur in real text files. Allowed:
 * tab, LF, VT, FF, CR, and SUB (legacy end-of-file marker).
 */
const isBinaryControl = (code: number): boolean =>
  code <= 0x08 || (code >= 0x0e && code <= 0x19) || (code >= 0x1b && code <= 0x1f);
