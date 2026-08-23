<div align="center">

# filebouncer

catch suspicious uploads before they reach your app

<img width="700" height="400" alt="filebouncer-pic" src="https://github.com/user-attachments/assets/1c6ad73b-ddb0-4976-b97b-2ff320d54d40" />

</div>

**Detect files that aren't what they claim to be.**

filebouncer inspects untrusted files for structural and metadata-based threats before your application processes them — including MIME mismatches, unsafe archives, risky CSV/TSV cells, and polyglot files.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](package.json)
[![TypeScript](https://img.shields.io/badge/TypeScript-types%20included-blue)](src/index.ts)
[![CI](https://github.com/Ramzi-Abidi/fileBouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/Ramzi-Abidi/fileBouncer/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@filebouncer/core.svg)](https://www.npmjs.com/package/@filebouncer/core)

> **filebouncer is not antivirus.**  
> It detects file structure and metadata risks. Pair it with ClamAV or another malware scanner when you need malware detection too.

---

## CLI

Scan any file on disk — no application code required:

```bash
npx @filebouncer/core ./your-file.jpg
```

Example output when the file is a JPEG that also contains a ZIP:

```text
filebouncer v0.6.4

File: polyglot.jpg
Size: 38137 bytes
Detected MIME: image/jpeg

Findings:
  high     POLYGLOT_DETECTED
           File appears to match more than one format (image/jpeg and application/zip @ 38115)

Result: BLOCK
```

Example output for a normal image:

```text
filebouncer v0.6.4

File: photo.jpg
Size: 37961 bytes
Detected MIME: image/jpeg

Findings: (none)

Result: OK
```

To reproduce the blocked example locally: `cat photo.jpg secret.zip > polyglot.jpg`, then scan `polyglot.jpg`.

`npx @filebouncer/core` runs the CLI via the `core` bin (required for scoped packages). After install, `filebouncer` works too. Use `--json` only when you need machine-readable output for scripts.

Exit codes: `0` = OK · `1` = BLOCK · `2` = unexpected error · `3` = usage error.

---

## Quick start

```bash
npm install @filebouncer/core
```

```ts
import { FileSecurityEngine } from "@filebouncer/core";

const engine = new FileSecurityEngine({
  scanners: ["mime", "metadata", "csv", "archive", "polyglot"],
  maxFileSize: 50 * 1024 * 1024,
});

const result = await engine.scan(uploadBuffer, {
  filename: "report.pdf",
  declaredMime: "application/pdf",
});

if (!result.ok) {
  console.log(result.threats);
}
```

`maxFileSize` defaults to **50 MiB** when omitted. Pass a different value to raise or lower the cap.

Enable stricter MIME checks with `mime: { strict: true, allowList: [...] }` — see [Usage](#usage).

One-off scan without creating an engine:

```ts
import { scanBuffer } from "@filebouncer/core";

const result = await scanBuffer(uploadBuffer, { filename: "report.pdf" });
```

---

## Why does this matter?

Checking a filename or `Content-Type` isn't enough.

A file called `photo.jpg` can contain more than a JPEG.

For example, a valid JPEG and a valid ZIP archive can be concatenated into a single file:

```text
photo.jpg + secret.zip
        ↓
   polyglot.jpg
```

The resulting file can still open as an image while also containing a valid ZIP archive.

The same problem appears in other forms:

- A `.jpg` whose actual bytes are not JPEG
- A client claiming `image/jpeg` while uploading another format
- Archives containing `../` paths
- Archives with extreme compression ratios
- Spreadsheet cells that can be interpreted as formulas by office software
- Files containing multiple recognizable formats

filebouncer is designed to catch these structural problems before they reach the rest of your application.

| Approach                     | Problem                                             |
| ---------------------------- | --------------------------------------------------- |
| Extension / MIME header only | Easy to spoof                                       |
| Hand-rolled archive checks   | Easy to miss edge cases                             |
| Antivirus alone              | Great for malware, not for structural upload issues |
| Heavy security platforms     | Often overkill for a Node upload endpoint           |

filebouncer fills the gap: **lightweight, typed, Node-native structural checks** you drop into Express, Fastify, or any pipeline.

---

## Status

**v0.6.4**. The scan engine, CLI, and MIME / metadata / CSV / archive / polyglot scanners are available. Public API may still evolve.

---

## Overview

Results follow a clear model:

- **Findings** → `result.threats[]` (e.g. `MIME_MISMATCH`, `UNSAFE_ENTRY_PATH`)
- **Scan failures** → `result.errors[]` (scanner crash, timeout)
- **Programmer mistakes** → throw `FileBouncerError` (bad config, unsupported input)

`result.ok` is `true` only when nothing met `blockThreshold` **and** the scan finished without errors or timeout. Detections and scan failures are **returned as data**, not thrown — your middleware can still inspect `threats` / `errors` for details.

### Scan budgets and early stopping

`timeoutMs` is a soft budget checked before each scanner starts. It does not cancel a `scanner.scan()` already in progress, so one slow scanner can run past the budget. Once the budget has been exceeded, later scanners are skipped, `timedOut` is `true`, `errors` includes a `SCAN_TIMEOUT` entry, and `result.ok` is `false`.

`failFast: true` stops later scanners only after a `critical` finding. A `high` finding meets the default `blockThreshold` and makes `result.ok` false, but does not stop the remaining scanners by itself.

---

## What it checks

| Area                       | Description                                                      |
| -------------------------- | ---------------------------------------------------------------- |
| **Unsafe archive paths**   | Entry names that leave the extract directory                     |
| **Archive size limits**    | Too many entries, huge uncompressed size, extreme ratios         |
| **Encrypted ZIP entries**  | Password-protected payloads that cannot be inspected             |
| **MIME mismatches**        | Extension or declared MIME disagrees with file signature         |
| **Risky CSV/TSV cells**    | Cells that start with characters office apps may treat specially |
| **Unsafe archive entries** | Absolute paths, link entries, suspicious names                   |
| **Metadata anomalies**     | Double extensions, executable extensions on “documents”          |
| **Polyglot files**         | One buffer that looks like more than one format (e.g. image+ZIP) |

### What it does **not** detect

- Viruses, trojans, or malware signatures
- Anything requiring a running antivirus daemon

Pair filebouncer with ClamAV (or similar) if you need both **structural checks** and **malware** coverage.

---

## Features

- **Scan engine** — single entry point via `FileSecurityEngine.scan()`
- **CLI** — `npx @filebouncer/core <file>` (or `filebouncer` after install)
- **Buffer-first, small files** — simple in-memory model; size limits enforced early
- **Multiple input shapes** — `Buffer`, `Uint8Array`, `Blob`, `File`, streams, disk paths
- **Pluggable scanners** — implement `Scanner` or pass `customScanners` in config
- **Structured results** — severity, machine-readable `code`, human `message`
- **ESM-only, Node ≥ 20** — modern `import` / `export`, TypeScript types included
- **Small dependency set** — signature detection via [`file-type`](https://github.com/sindresorhus/file-type)

---

## Usage

### Scan a file

```ts
import { FileSecurityEngine } from "@filebouncer/core";

const engine = new FileSecurityEngine({
  scanners: ["mime"],
  maxFileSize: 10 * 1024 * 1024,
  mime: {
    strict: true,
    allowList: ["image/jpeg", "image/png", "application/pdf"],
  },
});

// Buffer upload (multer, etc.)
const result = await engine.scan(req.file.buffer, {
  filename: req.file.originalname,
  declaredMime: req.file.mimetype,
});

// Path on disk
const result2 = await engine.scan({ path: "/tmp/upload.zip" });

if (!result.ok) {
  // reject upload — result.threats has structured findings
}
```

### Custom scanner

```ts
import { FileSecurityEngine, type Scanner, type Threat } from "@filebouncer/core";

const noEmptyScanner: Scanner = {
  name: "no-empty",
  appliesTo: () => true,
  scan: async (ctx) => {
    const buf = await ctx.read();
    return buf.length === 0
      ? [
          {
            scanner: "no-empty",
            code: "EMPTY_FILE",
            severity: "medium",
            message: "File is empty",
          } satisfies Threat,
        ]
      : [];
  },
};

const engine = new FileSecurityEngine({ customScanners: [noEmptyScanner] });
const result = await engine.scan(buffer, { filename: "file.txt" });
```

### Advanced — low-level API

The engine uses these internally. You rarely need them directly unless building a custom pipeline.

**Normalize any upload shape:**

```ts
import { normalizeInput } from "@filebouncer/core";

const input = await normalizeInput(req.file.buffer, {
  filename: req.file.originalname,
  declaredMime: req.file.mimetype,
  maxBytes: 10 * 1024 * 1024,
});

const buffer = await input.read();
```

**Detect real file type from bytes** (used by the MIME scanner internally):

```ts
import { detectType } from "@filebouncer/core";

const detected = await detectType(buffer);
// { mime: "application/zip", ext: "zip" } or undefined
```

**Parse extension from filename:**

```ts
import { parseExtension } from "@filebouncer/core";

parseExtension("report.PDF"); // "pdf"
parseExtension("archive.tar.gz"); // "gz"
parseExtension(".bashrc"); // undefined
```

---

## Requirements

- **Node.js** ≥ 20
- **ESM** — `"type": "module"` in your project (or dynamic `import()`)

No ClamAV. No Docker sidecar. No native bindings.

---

## Installation

```bash
pnpm add @filebouncer/core
# or
npm install @filebouncer/core
```

Requires **Node.js ≥ 20** and an ESM project (`"type": "module"` or dynamic `import()`).

To develop from source:

```bash
git clone https://github.com/Ramzi-Abidi/fileBouncer.git
cd fileBouncer
pnpm install
pnpm build
```

---

## Development

```bash
git clone https://github.com/Ramzi-Abidi/fileBouncer.git
cd fileBouncer
pnpm install
pnpm build
pnpm typecheck
pnpm lint
pnpm test
```

---

## Contributing

Ways to help:

|     | What                                      | Start here                                                                                                                                                                                                    |
| --- | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ⭐  | Star the repo if filebouncer is useful    | [GitHub](https://github.com/Ramzi-Abidi/fileBouncer)                                                                                                                                                          |
| 🐛  | Report a detection miss or false positive | [Detection bypass](https://github.com/Ramzi-Abidi/fileBouncer/issues/new?template=detection-bypass.yml) · [False positive](https://github.com/Ramzi-Abidi/fileBouncer/issues/new?template=false-positive.yml) |
| 💡  | Propose a new format / structural check   | [New file format](https://github.com/Ramzi-Abidi/fileBouncer/issues/new?template=new-file-format.yml)                                                                                                         |
| 🔧  | Add or improve a detector                 | [CONTRIBUTING.md](CONTRIBUTING.md#writing-a-scanner)                                                                                                                                                          |
| 📖  | Improve documentation                     | PRs against `README.md` / `CONTRIBUTING.md` welcome                                                                                                                                                           |

Prefer a **minimal sample** or a short script that generates one. Do not upload malware.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and PR guidelines.

---

## Roadmap

- [x] Public types & `ScanResult` model
- [x] Input normalization
- [x] File signature detection (`detectType`)
- [x] Scan engine (`FileSecurityEngine`)
- [x] MIME scanner
- [x] Metadata scanner
- [x] CSV scanner
- [x] Archive scanner
- [x] First npm release
- [x] Polyglot scanner
- [x] CLI (`filebouncer` / `npx @filebouncer/core`)
- [ ] Express & Fastify middleware
- [ ] Stable `v1.0.0` API

---

## License

[MIT](LICENSE) © filebouncer contributors
