# Contributing to filebouncer

Thank you for considering contributing to filebouncer! We appreciate your time and effort in making this project better. Please take a moment to review the following guidelines before getting started.

## Getting Started

1. Fork the repository and clone it locally.

   ```bash
   git clone https://github.com/Ramzi-Abidi/file-detection-engine.git
   cd file-detection-engine
   ```

2. Create a new branch for your feature or bug fix.

   ```bash
   git checkout -b feat/your-feature
   ```

3. Install dependencies (requires Node.js >= 22 and pnpm).

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
   git fetch upstream
   git rebase upstream/main
   ```

8. Create a pull request against the `main` branch.

9. Add a **description** explaining what your PR does and why.

## Project Structure

```
src/
  engine/          — FileSecurityEngine, budgets, verdict logic
  scanners/        — Built-in scanners (mime, metadata, csv, archive)
  util/            — Helpers (detectType)
  input.ts         — Input normalization
  types.ts         — Public type surface
  index.ts         — Package entry point / exports
test/
  scanners/        — Scanner tests (one file per scanner)
```

## Code Style

- Run `pnpm format` before committing (Prettier handles formatting).
- Use clear and descriptive variable and function names.
- Prefer classes for scanners (`class FooScanner implements Scanner`).
- Keep module-level helpers as plain functions only when they are stateless.
- Avoid comments that just narrate what code does — only explain the "why" when non-obvious.

## Writing a Scanner

Each built-in scanner follows this pattern:

1. Create `src/scanners/your-scanner.ts` with a class implementing `Scanner`.
2. Add config interface to `src/types.ts` if needed.
3. Wire it in `src/engine/built-ins.ts`.
4. Export from `src/scanners/index.ts` and `src/index.ts`.
5. Add tests in `test/scanners/your-scanner.test.ts`.

## Pull Request Guidelines

- Keep PRs **small and focused** — one scanner or feature per PR.
- All checks must pass: `typecheck`, `lint`, `test`, `build`.
- Include tests for new functionality.
- Update the README roadmap if your PR ships a new scanner.

## Issues and Discussions

- Feel free to open an issue for bug reports or feature requests.
- Participate in discussions on existing issues.
- If you're unsure about an approach, open an issue to discuss before writing code.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

Thanks for your contribution!
