# filebouncer

**Structural file-abuse detection for Node.js**, ZIP slip, ZIP bombs, MIME spoofing, CSV injection, and unsafe archive entries.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](package.json)
[![TypeScript](https://img.shields.io/badge/TypeScript-types%20included-blue)](src/index.ts)
[![CI](https://github.com/Ramzi-Abidi/file-detection-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/Ramzi-Abidi/file-detection-engine/actions/workflows/ci.yml)

> **filebouncer is not antivirus.**  
> it catches **file abuse**, attacks that exploit how your app handles uploads.

---

## Status

**Early development** (`v0.0.0`). The scan engine, MIME, metadata, and CSV scanners are available; more built-in scanners are coming next. Public API may change until `v1.0.0`.

---

## Quick start

See [Installation](#installation) to clone and build. Then:

```ts
import { FileSecurityEngine } from "filebouncer";

const engine = new FileSecurityEngine({
  scanners: ["mime", "metadata", "csv"],
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
import { scanBuffer } from "filebouncer";

const result = await scanBuffer(uploadBuffer, { filename: "report.pdf" });
```

---

## Overview

Upload pipelines need more than “check the file extension.” Attackers rename executables as images, hide path traversal inside ZIP entries, or trigger formula injection in CSV exports.

**filebouncer** is a small, modular scanning layer for Node.js. It inspects file **structure and behavior** — the things that break apps even when no virus is involved.

Results follow a **ClamAV-style model**:

- **Findings** → `result.threats[]` (e.g. `ZIP_SLIP`, `MIME_MISMATCH`)
- **Scan failures** → `result.errors[]` (corrupt archive, timeout)
- **Programmer mistakes** → throw `FileBouncerError` (bad config, unsupported input)

Detections are **returned as data**, not thrown -> your middleware decides whether to reject the upload.

---

## Why filebouncer

| Approach                     | Problem                                                              |
| ---------------------------- | -------------------------------------------------------------------- |
| Extension / MIME header only | Trivial to spoof                                                     |
| Roll your own ZIP checks     | Easy to miss ZIP slip, bombs, symlinks                               |
| ClamAV / antivirus           | Great for malware, **does not** catch MIME spoofing or CSV injection |
| Heavy security platforms     | Overkill for many Node upload endpoints                              |

filebouncer fills the gap: **lightweight, typed, Node-native structural checks** you drop into Express, Fastify, or any pipeline.

---

## What it detects

| Threat                     | Description                                                 |
| -------------------------- | ----------------------------------------------------------- |
| **ZIP slip**               | Path traversal via archive entry names (`../../etc/passwd`) |
| **ZIP bombs**              | Compression ratio / entry count / nested archive explosions |
| **MIME spoofing**          | Extension or declared MIME disagrees with file signature    |
| **CSV injection**          | Cells starting with `=`, `+`, `-`, `@` (formula injection)  |
| **Unsafe archive entries** | Absolute paths, symlinks, suspicious names                  |
| **Metadata anomalies**     | Double extensions, executable extensions on “documents”     |

### What it does **not** detect

- Viruses, trojans, or malware signatures
- Anything requiring a running antivirus daemon

Pair filebouncer with ClamAV (or similar) if you need both **structural abuse** and **malware** coverage.

---

## Features

- **Scan engine** — single entry point via `FileSecurityEngine.scan()`
- **Buffer-first, small files** — simple in-memory model; size limits enforced early
- **Multiple input shapes** — `Buffer`, `Uint8Array`, `Blob`, `File`, streams, disk paths
- **Pluggable scanners** — implement `Scanner` or pass `customScanners` in config
- **Structured results** — severity, machine-readable `code`, human `message`
- **ESM-only, Node ≥ 20** — modern `import` / `export`, TypeScript types included
- **One runtime dependency** — `[file-type](https://github.com/sindresorhus/file-type)` for signature detection

---

## Usage

### Scan a file

```ts
import { FileSecurityEngine } from "filebouncer";

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
import { FileSecurityEngine, type Scanner, type Threat } from "filebouncer";

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
import { normalizeInput } from "filebouncer";

const input = await normalizeInput(req.file.buffer, {
  filename: req.file.originalname,
  declaredMime: req.file.mimetype,
  maxBytes: 10 * 1024 * 1024,
});

const buffer = await input.read();
```

**Detect real file type from bytes** (used by the MIME scanner internally):

```ts
import { detectType } from "filebouncer";

const detected = await detectType(buffer);
// { mime: "application/zip", ext: "zip" } or undefined
```

**Parse extension from filename:**

```ts
import { parseExtension } from "filebouncer";

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

Not published to npm yet. Clone and build from GitHub:

```bash
git clone https://github.com/Ramzi-Abidi/file-detection-engine.git
cd file-detection-engine
pnpm install
pnpm build
```

Use as a local dependency in another project:

```bash
pnpm add file:../file-detection-engine
```

When the first npm release ships, install with:

```bash
pnpm add filebouncer
```

---

## Development

```bash
git clone https://github.com/Ramzi-Abidi/file-detection-engine.git
cd file-detection-engine
pnpm install
pnpm build
pnpm typecheck
pnpm lint
pnpm test
```

---

## Roadmap

- [x] Public types & `ScanResult` model
- [x] Input normalization
- [x] File signature detection (`detectType`)
- [x] Scan engine (`FileSecurityEngine`)
- [x] MIME scanner
- [x] Metadata scanner
- [x] CSV injection scanner
- [ ] Built-in scanners (archive, polyglot)
- [ ] Express & Fastify middleware
- [ ] v1.0.0 on npm

---

## License

[MIT](LICENSE) © filebouncer contributors
