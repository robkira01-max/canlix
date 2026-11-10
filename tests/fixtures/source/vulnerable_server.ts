/**
 * Vulnerable TypeScript MCP server — one finding per rule expected.
 * DO NOT USE in production. For testing only.
 */

import { exec, execSync, spawn } from "child_process";

// TS-014: debug mode hardcoded (MEDIUM)
const NODE_ENV = "development";

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

// TS-009: SQL injection — template literal in db.query (HIGH)
export function getUser(userId: string): Promise<unknown> {
  return db.query(`SELECT * FROM users WHERE id = ${userId}`);
}

// TS-010: insecure PRNG for session token (MEDIUM)
export function generateSessionToken(): string {
  const token = Math.random().toString(36).substring(2);
  return token;
}

// TS-011: TLS certificate verification disabled (HIGH)
const tlsOptions = { rejectUnauthorized: false };

// TS-012: weak hash algorithm (MEDIUM)
import crypto from "crypto";
const hash = crypto.createHash("md5").update("data").digest("hex");

// TS-013: non-constant-time comparison on a secret token (MEDIUM)
function verifyToken(storedToken: string, userToken: string): boolean {
  return storedToken === userToken;
}

// TS-017: insecure cookie — missing httpOnly and secure (MEDIUM)
function setSession(res: any, token: string): void {
  res.cookie("session", token, { sameSite: "strict" });
}

// TS-016: JWT algorithm confusion — algorithms: ['none'] (HIGH)
const jwtOptions = { algorithms: ["none"] };

// TS-015: open redirect — res.redirect with variable URL (MEDIUM)
function handleRedirect(res: any, url: string): void {
  res.redirect(url);
}
