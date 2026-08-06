# filebouncer

**Structural file validation for Node** checks uploads for MIME mismatches, unsafe archive entries, oversized archives, and risky spreadsheet cells.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](package.json)
[![TypeScript](https://img.shields.io/badge/TypeScript-types%20included-blue)](src/index.ts)
[![CI](https://github.com/Ramzi-Abidi/fileBouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/Ramzi-Abidi/fileBouncer/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@filebouncer/core.svg)](https://www.npmjs.com/package/@filebouncer/core)

> **filebouncer is not antivirus.**  
> It checks **file structure and metadata** so your upload pipeline can reject unsafe files early.

---

## Status

**v0.3.0**. The scan engine plus MIME, metadata, CSV, and archive scanners are available. Public API may still evolve.

---

## Quick start

```bash
npm install @filebouncer/core
```

```ts
import { FileSecurityEngine } from "@filebouncer/core";

const engine = new FileSecurityEngine({
  scanners: ["mime", "metadata", "csv", "archive"],
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

Enable stricter MIME checks with `mime: { strict: true, allowList: [...] }` — see [Usage](#usage).

One-off scan without creating an engine:

```ts
import { scanBuffer } from "@filebouncer/core";

const result = await scanBuffer(uploadBuffer, { filename: "report.pdf" });
```

---

## Overview

Upload pipelines need more than “check the file extension.” Files can claim the wrong type, carry unsafe archive entry names, or include spreadsheet cells that are risky when opened in office software.

**filebouncer** is a small, modular scanning layer for Node.js. It inspects file **structure and behavior** — the things that break apps even when no malware signature is involved.

Results follow a clear model:

- **Findings** → `result.threats[]` (e.g. `MIME_MISMATCH`, `UNSAFE_ENTRY_PATH`)
- **Scan failures** → `result.errors[]` (corrupt archive, timeout)
- **Programmer mistakes** → throw `FileBouncerError` (bad config, unsupported input)

Detections are **returned as data**, not thrown — your middleware decides whether to reject the upload.

---

## Why filebouncer

| Approach                     | Problem                                                              |
| ---------------------------- | -------------------------------------------------------------------- |
| Extension / MIME header only | Easy to spoof                                                        |
| Hand-rolled archive checks   | Easy to miss edge cases                                              |
| Antivirus alone              | Great for malware, not for structural upload issues                  |
| Heavy security platforms     | Often overkill for a Node upload endpoint                            |

filebouncer fills the gap: **lightweight, typed, Node-native structural checks** you drop into Express, Fastify, or any pipeline.

---

## What it checks

| Area                       | Description                                              |
| -------------------------- | -------------------------------------------------------- |
| **Unsafe archive paths**   | Entry names that leave the extract directory             |
| **Archive size limits**    | Too many entries, huge uncompressed size, extreme ratios |
| **MIME mismatches**        | Extension or declared MIME disagrees with file signature |
| **Risky spreadsheet cells**| Cells that start with characters office apps may treat specially |
| **Unsafe archive entries** | Absolute paths, link entries, suspicious names           |
| **Metadata anomalies**     | Double extensions, executable extensions on “documents”  |

### What it does **not** detect

- Viruses, trojans, or malware signatures
- Anything requiring a running antivirus daemon

Pair filebouncer with ClamAV (or similar) if you need both **structural checks** and **malware** coverage.

---

## Features

- **Scan engine** — single entry point via `FileSecurityEngine.scan()`
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

See [CONTRIBUTING.md](CONTRIBUTING.md) for PR guidelines.

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
- [ ] Polyglot scanner
- [ ] Express & Fastify middleware
- [ ] Stable `v1.0.0` API

---

## License

[MIT](LICENSE) © filebouncer contributors
