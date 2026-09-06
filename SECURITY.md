# Security policy

filebouncer is **not antivirus**. It performs structural and metadata checks on uploaded files.

## Supported versions

Only the latest published `@filebouncer/core` release is supported.

| Version | Supported |
| ------- | --------- |
| 0.6.x (latest on npm) | Yes |
| < 0.6.5 | No |

## What to report privately

Use a **private** report if public details would help someone bypass upload checks:

- A file that should have been blocked or failed closed, but was accepted (`ok: true`, empty `errors`)
- Fail-open on corrupt or encrypted archives
- Path / zip-slip / size-bomb cases the scanner misses
- Anything that leaks file contents or secrets from the host

## What to report in public issues

- False positives
- Docs / API questions
- New format requests
- Bypasses you can describe **without** a ready-to-abuse sample (or with a tiny generated fixture)

Use [Detection bypass](https://github.com/Ramzi-Abidi/fileBouncer/issues/new?template=detection-bypass.yml) or [False positive](https://github.com/Ramzi-Abidi/fileBouncer/issues/new?template=false-positive.yml).

## How to report privately

Open a [GitHub Security Advisory](https://github.com/Ramzi-Abidi/fileBouncer/security/advisories/new).

Include:

- `@filebouncer/core` version
- Engine config (`scanners`, `blockThreshold`, relevant scanner options)
- What you expected vs `ScanResult` (`ok`, `threats`, `errors`, `scannersRun`)
- A **minimal generated** sample or a short script that builds one

Do **not** upload malware, or files you do not have rights to share.

## Scope

Out of scope:

- Malware that needs an antivirus engine
- Issues only in the host app (auth, rate limits, storage ACLs)
- Theoretical issues with no repro
