/**
 * Vulnerable TypeScript MCP server — one finding per rule expected.
 * DO NOT USE in production. For testing only.
 */

import { exec, execSync, spawn } from "child_process";

// TS-001: hardcoded GitHub token (key prefix — CRITICAL)
const GH_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890ab";

// TS-002: eval — arbitrary code execution (HIGH)
export function dangerousEval(userInput: string): unknown {
  return eval(userInput);
}

// TS-003: execSync — shell-equivalent (HIGH)
export function runSync(cmd: string): string {
  return execSync(cmd).toString();
}

// TS-004: spawn with shell: true (HIGH)
export function spawnShell(cmd: string): void {
  spawn(cmd, { shell: true });
}

// TS-005: exec with template literal (HIGH)
export function runTemplate(input: string): void {
  exec(`ls ${input}`);
}

// TS-006: prototype pollution (MEDIUM)
export function mergeUnsafe(
  obj: Record<string, unknown>,
  source: Record<string, unknown>,
): void {
  (obj as Record<string, unknown>).__proto__ = source;
}

// TS-007: SSRF — fetch with variable URL (MEDIUM)
export async function fetchRemote(url: string): Promise<Response> {
  return fetch(url);
}

// TS-008: path traversal — fs.readFile with variable path (MEDIUM)
import * as fs from "fs";
export function readFile(filePath: string): void {
  fs.readFile(filePath, "utf8", () => {});
}
