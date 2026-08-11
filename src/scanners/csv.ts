import type { CsvConfig, Scanner, ScannerContext, Threat } from "../types";

const DEFAULT_PREFIXES = ["=", "+", "@", "\t", "\r"];
const DEFAULT_MAX_ROWS = 10_000;

const CSV_EXTENSIONS = ["csv", "tsv"];
const CSV_MIMES = ["text/csv", "application/csv", "text/tab-separated-values"];

export class CsvScanner implements Scanner {
  readonly name = "csv";

  private readonly prefixes: string[];
  private readonly maxRows: number;
  private readonly delimiter: string | undefined;

  constructor(private readonly config: CsvConfig = {}) {
    this.prefixes = config.prefixes ?? DEFAULT_PREFIXES;
    this.maxRows = config.maxRows ?? DEFAULT_MAX_ROWS;
    this.delimiter = config.delimiter;
  }

  appliesTo(ctx: ScannerContext) {
    if (ctx.extension && CSV_EXTENSIONS.includes(ctx.extension)) return true;
    if (ctx.detectedMime && CsvScanner.isCsvMime(ctx.detectedMime)) return true;
    if (ctx.declaredMime && CsvScanner.isCsvMime(ctx.declaredMime)) return true;
    return false;
  }

  async scan(ctx: ScannerContext) {
    const threats: Threat[] = [];
    const buffer = await ctx.read();
    if (buffer.length === 0) return threats;

    const text = buffer.toString("utf8");
    const lines = text.split(/\r?\n/).filter((line) => line.length > 0);
    if (lines.length === 0) return threats;

    const delimiter = this.delimiter ?? CsvScanner.detectDelimiter(lines[0]!);
    const rowLimit = this.maxRows === 0 ? lines.length : Math.min(this.maxRows, lines.length);

    for (let rowIndex = 0; rowIndex < rowLimit; rowIndex++) {
      const cells = CsvScanner.parseLine(lines[rowIndex]!, delimiter);

      for (let columnIndex = 0; columnIndex < cells.length; columnIndex++) {
        const cell = cells[columnIndex]!;
        if (!this.isDangerousCell(cell)) continue;

        threats.push({
          scanner: this.name,
          code: "CSV_UNSAFE_CELL",
          severity: "high",
          message: `Cell at row ${String(rowIndex + 1)}, column ${String(columnIndex + 1)} starts with a disallowed prefix`,
          meta: {
            row: rowIndex + 1,
            column: columnIndex + 1,
            value: cell.length > 100 ? `${cell.slice(0, 100)}…` : cell,
            prefix: this.matchingPrefix(cell),
          },
        });
      }
    }

    return threats;
  }

  private isDangerousCell(cell: string) {
    return this.matchingPrefix(cell) !== undefined;
  }

  private matchingPrefix(cell: string) {
    for (const prefix of this.prefixes) {
      if (prefix === "\t" || prefix === "\r") {
        if (cell.startsWith(prefix)) return prefix;
        continue;
      }

      if (cell.trimStart().startsWith(prefix)) return prefix;
    }

    return undefined;
  }

  private static isCsvMime(mime: string) {
    const normalized = mime.split(";")[0]!.trim().toLowerCase();
    return CSV_MIMES.includes(normalized);
  }

  private static detectDelimiter(firstLine: string) {
    const candidates = [",", ";", "\t"];
    let best = ",";
    let bestCount = 0;

    for (const candidate of candidates) {
      const count = firstLine.split(candidate).length - 1;
      if (count > bestCount) {
        bestCount = count;
        best = candidate;
      }
    }

    return best;
  }

  private static parseLine(line: string, delimiter: string) {
    const fields: string[] = [];
    let current = "";
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
      const char = line[i]!;

      if (inQuotes) {
        if (char === '"') {
          if (line[i + 1] === '"') {
            current += '"';
            i++;
          } else {
            inQuotes = false;
          }
        } else {
          current += char;
        }
        continue;
      }

      if (char === '"') {
        inQuotes = true;
      } else if (char === delimiter) {
        fields.push(current);
        current = "";
      } else {
        current += char;
      }
    }

    fields.push(current);
    return fields;
  }
}
