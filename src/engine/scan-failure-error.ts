/**
 * Thrown by a scanner when it cannot complete its analysis due to a
 * structural problem with the input (e.g. corrupt archive, empty file).
 *
 * The engine maps this to a {@link ScanError} with the provided `code`,
 * rather than the generic `"SCANNER_ERROR"`.
 */
export class ScanFailureError extends Error {
  constructor(
    readonly code: string,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}
