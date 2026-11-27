import { fileTypeFromBuffer } from "file-type";

import { CFB_MIME } from "./mime";
import { isUtf16Text } from "./text-type";

export interface DetectedType {
  mime: string;
  ext: string;
}

/**
 * Detect the file type from the start of a buffer (file signature).
 * Returns undefined when the type is unknown (e.g. plain text, empty).
 */
export async function detectType(buffer: Buffer): Promise<DetectedType | undefined> {
  // UTF-16 text (e.g. Excel "Unicode Text") would otherwise be reported as MPEG audio.
  if (isUtf16Text(buffer)) return undefined;

  const result = await fileTypeFromBuffer(buffer);
  if (!result) {
    return undefined;
  }
  if (result.mime === CFB_MIME && isWindowsInstaller(buffer)) {
    return { mime: "application/x-msi", ext: "msi" };
  }
  return { mime: result.mime, ext: result.ext };
}

/**
 * Legacy Office files and Windows Installer packages (.msi/.msp/.mst) share
 * the Compound File Binary container, so `file-type` reports both as `cfb`.
 * Installers are identified by the CLSID stored on the container's root
 * directory entry: {000C108x-0000-0000-C000-000000000046}.
 */
function isWindowsInstaller(buffer: Buffer): boolean {
  if (buffer.length < 0x34) return false;
  const sectorShift = buffer.readUInt16LE(0x1e);
  if (sectorShift !== 9 && sectorShift !== 12) return false;

  const firstDirectorySector = buffer.readUInt32LE(0x30);
  const rootEntryOffset = (firstDirectorySector + 1) * 2 ** sectorShift;
  const clsidOffset = rootEntryOffset + 0x50;
  if (clsidOffset + 16 > buffer.length) return false;

  const clsid = buffer.subarray(clsidOffset, clsidOffset + 16);
  return (clsid[0]! & 0xf0) === 0x80 && clsid.subarray(1, 16).equals(MSI_CLSID_TAIL);
}

/** Bytes 1..15 of the little-endian MSI-family CLSID (byte 0 varies: 0x82/0x84/0x86). */
const MSI_CLSID_TAIL = Buffer.from([
  0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
]);
