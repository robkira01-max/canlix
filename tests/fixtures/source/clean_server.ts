/**
 * Clean TypeScript MCP server — no security findings expected.
 */

import * as childProcess from "child_process";
import * as fs from "fs";
import * as path from "path";

const BASE_DIR = process.env.DATA_DIR ?? "/home/user/data";
const API_KEY = process.env.API_KEY ?? "";
const DB_PASSWORD = process.env.DB_PASSWORD ?? "";

export async function handleRequest(
  data: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return { status: "ok", result: data };
}

export function runSafe(cmd: string, args: string[]): string {
  const result = childProcess.execFileSync(cmd, args, { encoding: "utf-8" });
  return result;
}

export function spawnSafe(cmd: string, args: string[]): childProcess.ChildProcess {
  return childProcess.spawn(cmd, args, { shell: false });
}

export function loadConfig(filePath: string): Record<string, unknown> {
  const resolved = path.resolve(BASE_DIR, path.basename(filePath));
  const content = fs.readFileSync(resolved, "utf-8");
  return JSON.parse(content);
}

export function mergeSettings(
  base: Record<string, unknown>,
  overrides: Record<string, unknown>,
): Record<string, unknown> {
  const copy = Object.create(null) as Record<string, unknown>;
  for (const [k, v] of Object.entries(base)) {
    copy[k] = v;
  }
  for (const [k, v] of Object.entries(overrides)) {
    if (k !== "__proto__" && k !== "constructor") {
      copy[k] = v;
    }
  }
  return copy;
}
