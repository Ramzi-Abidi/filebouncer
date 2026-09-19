import { promises as fs } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { FileSecurityEngine } from "../src/engine/file-security-engine";
import { InputTooLargeError, normalizeInput } from "../src/input";

describe("path input", () => {
  let directory: string;
  let filePath: string;
  let handles: FileHandle[];

  beforeEach(async () => {
    directory = await fs.mkdtemp(path.join(tmpdir(), "filebouncer-input-"));
    filePath = path.join(directory, "upload.txt");
    handles = [];
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await Promise.all(handles.map((handle) => handle.close()));
    await fs.rm(directory, { recursive: true, force: true });
  });

  async function changeAfterStat(change: () => Promise<void>) {
    const stats = await fs.stat(filePath);
    const handle = await fs.open(filePath, "r");
    handles.push(handle);
    vi.spyOn(fs, "stat").mockImplementationOnce(async () => {
      await change();
      return stats;
    });
    vi.spyOn(fs, "open").mockResolvedValueOnce(handle);
    vi.spyOn(handle, "stat").mockResolvedValueOnce(stats);
    return {
      read: vi.spyOn(handle, "read"),
      close: vi.spyOn(handle, "close"),
    };
  }

  it.each([0, 4, 65536, 65537])(
    "accepts exactly %i bytes and memoizes the result",
    async (size) => {
      const data = Buffer.alloc(size, "a");
      await fs.writeFile(filePath, data);

      const input = await normalizeInput({ path: filePath }, { maxBytes: size });
      const buffer = await input.read();

      expect(input.size).toBe(size);
      expect(buffer).toEqual(data);
      expect(await input.read()).toBe(buffer);
    },
  );

  it("rejects an already oversized file", async () => {
    await fs.writeFile(filePath, "12345");
    await expect(normalizeInput({ path: filePath }, { maxBytes: 4 })).rejects.toBeInstanceOf(
      InputTooLargeError,
    );
  });

  it("bounds reads when the file grows beyond the size limit", async () => {
    await fs.writeFile(filePath, "abc");
    const io = await changeAfterStat(() => fs.appendFile(filePath, Buffer.alloc(1024)));

    await expect(normalizeInput({ path: filePath }, { maxBytes: 4 })).rejects.toMatchObject({
      name: "InputTooLargeError",
      observedAtLeast: 5,
      maxBytes: 4,
    });
    expect(io.read).toHaveBeenCalledTimes(1);
    expect(io.read).toHaveBeenCalledWith(expect.any(Buffer), 0, 5, null);
    expect(io.close).toHaveBeenCalledOnce();
  });

  it.each(["abcdef", "a"])("reports actual size after the file changes to %s", async (data) => {
    await fs.writeFile(filePath, "abc");
    const io = await changeAfterStat(() => fs.writeFile(filePath, data));

    const input = await normalizeInput(
      { path: filePath },
      { maxBytes: 10, filename: "REPORT.CSV", declaredMime: "text/csv" },
    );

    expect(input.size).toBe(Buffer.byteLength(data));
    expect(await input.read()).toEqual(Buffer.from(data));
    expect(input.filename).toBe("REPORT.CSV");
    expect(input.extension).toBe("csv");
    expect(input.declaredMime).toBe("text/csv");
    expect(io.close).toHaveBeenCalledOnce();
  });

  it("reads the opened file when its path is replaced", async () => {
    await fs.writeFile(filePath, "abc");
    const io = await changeAfterStat(async () => {
      await fs.rename(filePath, path.join(directory, "original.txt"));
      await fs.writeFile(filePath, "too large");
    });

    const input = await normalizeInput({ path: filePath }, { maxBytes: 4 });

    expect(input.size).toBe(3);
    expect(await input.read()).toEqual(Buffer.from("abc"));
    expect(io.close).toHaveBeenCalledOnce();
  });

  it("closes the handle when reading fails", async () => {
    await fs.writeFile(filePath, "abc");
    const io = await changeAfterStat(() => Promise.resolve());
    const error = new Error("read failed");
    io.read.mockRejectedValueOnce(error);

    await expect(normalizeInput({ path: filePath })).rejects.toBe(error);
    expect(io.close).toHaveBeenCalledOnce();
  });

  it("converts growth beyond maxFileSize into an engine threat", async () => {
    await fs.writeFile(filePath, "abc");
    await changeAfterStat(() => fs.appendFile(filePath, "defgh"));
    const engine = new FileSecurityEngine({ scanners: [], maxFileSize: 4 });

    const result = await engine.scan({ path: filePath });

    expect(result.ok).toBe(false);
    expect(result.size).toBe(5);
    expect(result.threats).toEqual([
      expect.objectContaining({ code: "FILE_TOO_LARGE", severity: "critical" }),
    ]);
    expect(result.scannersRun).toEqual([]);
  });

  it("rejects directories before opening them", async () => {
    const open = vi.spyOn(fs, "open");
    await expect(normalizeInput({ path: directory })).rejects.toThrow("not a regular file");
    expect(open).not.toHaveBeenCalled();
  });
});
