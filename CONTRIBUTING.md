# Contributing to filebouncer

Thanks for helping make upload pipelines safer. This project focuses on **structural and metadata** checks — not antivirus signatures.

## Ways to contribute

| Goal | What to do |
| ---- | ---------- |
| Report a bypass | Open [Detection bypass](https://github.com/Ramzi-Abidi/fileBouncer/issues/new?template=detection-bypass.yml) |
| Report a false positive | Open [False positive](https://github.com/Ramzi-Abidi/fileBouncer/issues/new?template=false-positive.yml) |
| Suggest a new detection | Open [New file format](https://github.com/Ramzi-Abidi/fileBouncer/issues/new?template=new-file-format.yml) |
| Add a detector | Follow [Writing a scanner](#writing-a-scanner) |
| Add a regression case | Prefer a **generated** buffer in `test/` (see existing polyglot/archive tests). Tiny committed fixtures only when generation is impractical. |
| Improve docs | Edit `README.md` or this file |

**Safety:** share minimal structural samples only. Do not upload malware or files you do not have rights to share.

## Getting started

1. Fork the repository and clone it locally.

   ```bash
   git clone https://github.com/Ramzi-Abidi/fileBouncer.git
   cd fileBouncer
   ```

2. Create a new branch for your feature or bug fix.

   ```bash
   git checkout -b feat/your-feature
   ```

3. Install dependencies (requires Node.js ≥ 20 and pnpm).

   ```bash
   pnpm install
   ```

4. Make your changes and verify everything passes.

   ```bash
   pnpm typecheck
   pnpm lint
   pnpm test
   pnpm build
   ```

5. Commit your changes with a clear and concise commit message.

   ```bash
   git commit -m "feat(scanner): description of your changes"
   ```

6. Push your branch to your fork.

   ```bash
   git push origin feat/your-feature
   ```

7. Before creating a pull request, rebase with main to avoid conflicts.

   ```bash
   git fetch
   git rebase main
   ```

8. Create a pull request against the `main` branch.

9. Add a **description** explaining what your PR does and why.

## Project structure

```
src/
  engine/          — FileSecurityEngine, budgets, verdict logic
  scanners/        — Built-in scanners (mime, metadata, csv, archive, polyglot)
  util/            — Helpers (detectType)
  cli.ts           — filebouncer CLI (bin entry)
  input.ts         — Input normalization
  types.ts         — Public type surface
  index.ts         — Package entry point / exports
test/
  engine/          — Engine orchestration tests
  scanners/        — Scanner tests (one file per scanner)
  cli.test.ts      — CLI argument parsing and smoke runs
```

## Code style

- Run `pnpm format` before committing (Prettier handles formatting).
- Use clear and descriptive variable and function names.
- Prefer classes for scanners (`class FooScanner implements Scanner`).
- Keep module-level helpers as plain functions only when they are stateless.
- Avoid comments that just narrate what code does — only explain the "why" when non-obvious.

## Writing a scanner

Each built-in scanner follows this pattern:

1. Create `src/scanners/your-scanner.ts` with a class implementing `Scanner`.
2. Add a config interface to `src/types.ts` if needed.
3. Wire it in `src/engine/built-ins.ts`.
4. Export from `src/scanners/index.ts` and `src/index.ts`.
5. Add tests in `test/scanners/your-scanner.test.ts` (prefer generating samples in the test).
6. Update the README roadmap / “What it checks” if you ship a new scanner.

## Pull request guidelines

- Keep PRs **small and focused** — one scanner or feature per PR.
- All checks must pass: `typecheck`, `lint`, `test`, `build`.
- Include tests for new functionality.
- For detection changes, include a failing case before the fix when possible.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

Thanks for your contribution!
