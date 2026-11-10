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

// TS-018: XXE — DOMParser with variable XML input (HIGH)
function parseXml(xmlData: string): Document {
  return new DOMParser().parseFromString(xmlData, "text/xml");
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

// TS-019: unsafe deserialization — node-serialize
import serialize from "node-serialize";
function loadObject(data: string): unknown {
  return serialize.unserialize(data);
}

// TS-020: hardcoded cryptographic key in createCipheriv
function encryptData(plaintext: Buffer): Buffer {
  const cipher = crypto.createCipheriv("aes-256-gcm", "hardcoded_32_byte_key_1234567890a", iv);
  return cipher.update(plaintext);
}

// TS-021: CORS wildcard — any origin allowed
const corsOptions = { "Access-Control-Allow-Origin": "*" };

// TS-022: SSTI — ejs.render with user-controlled template string
import ejs from "ejs";
function renderTemplate(template: string): string {
  return ejs.render(template, {});
}

// TS-023: ReDoS — new RegExp with user-controlled pattern
function filterItems(pattern: string, items: string[]): string[] {
  return items.filter((x) => new RegExp(pattern).test(x));
}

// TS-024: sensitive value logged
function logLogin(password: string): void {
  console.log("Login attempt", password);
}

// TS-025: security header removed
function unsafeRoute(res: any): void {
  res.removeHeader("x-frame-options");
}

// TS-026: mass assignment via req.body spread
function createUser(req: any, user: any): void {
  Object.assign(user, req.body);
}

// TS-027: path traversal — path.join with user-controlled segment
import path from "path";
function serveFile(baseDir: string, filename: string): string {
  return path.join(baseDir, filename);
}

// TS-028: fixed PRNG seed
import seedrandom from "seedrandom";
const rng = seedrandom("fixedSeed");

// TS-029: password hashed with fast algorithm
function hashPassword(password: string): string {
  return crypto.createHash("sha256").update(password).digest("hex");
}

// TS-030: assert used for access control
function adminRoute(user: any): void {
  assert(user.isAuthenticated);
}

// TS-031: sensitive data stored in localStorage
function cacheToken(token: string): void {
  localStorage.setItem("token", token);
}

// TS-032: hardcoded JWT secret
import jwt from "jsonwebtoken";
function signToken(payload: object): string {
  return jwt.sign(payload, "hardcoded_jwt_secret_key_12345");
}

// TS-033: DOM XSS via innerHTML assignment
function displayMessage(msg: string): void {
  document.getElementById("output")!.innerHTML = msg;
}

// TS-034: unsafe YAML deserialization
import yaml from "js-yaml";
function loadConfig(raw: string): unknown {
  return yaml.load(raw);
}

// TS-035: hardcoded fallback for sensitive env var
const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret_key_123";

// TS-036: open redirect from request query param
function loginRedirect(res: any, req: any): void {
  res.redirect(req.query.next);
}

// TS-037: user-controlled executable in spawn — OS command injection
function runUserProgram(program: string): void {
  spawn(program, ["--config", "default.cfg"]);
}

// TS-038: world-writable file permissions
function makeFilePublic(filePath: string): void {
  fs.chmod(filePath, 0o777, () => {});
}

// TS-039: base64 used as obfuscation on a secret value
function encodePassword(password: string): string {
  return btoa(password);
}

// TS-040: new Function() with dynamic argument — runtime code injection
function runDynamic(userCode: string): unknown {
  return new Function(userCode)();
}

// TS-041: credentials embedded in connection-string URL
const DB_URL = "postgresql://admin:super_secret_pass@db.example.com/prod";

// TS-042: vm.runInNewContext with user-supplied code — vm is NOT a sandbox
import vm from "vm";
function runInSandbox(code: string): unknown {
  return vm.runInNewContext(code, {});
}
