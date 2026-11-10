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

export function runSafe(args: string[]): string {
  const result = childProcess.execFileSync("node", args, { encoding: "utf-8" });
  return result;
}

export function spawnSafe(args: string[]): childProcess.ChildProcess {
  return childProcess.spawn("node", args, { shell: false });
}

export function loadConfig(filePath: string): Record<string, unknown> {
  // path.basename strips directory components — only the filename is used
  const safeName = path.basename(filePath);
  const content = fs.readFileSync(`${BASE_DIR}/${safeName}`, "utf-8");
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
