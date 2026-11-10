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

// TS-043: SQL injection via string concatenation
async function searchByName(term: string): Promise<unknown> {
  return db.query("SELECT * FROM users WHERE name = '" + term + "'");
}

// TS-044: header injection from request data
function setLocationHeader(res: any, req: any): void {
  res.setHeader("Location", req.query.returnUrl);
}

// TS-045: path traversal via res.sendFile with request data
function serveAttachment(res: any, req: any): void {
  res.sendFile(req.query.file);
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

// TS-046: fs.writeFile with user-controlled path from request
function saveUpload(req: any, data: Buffer): void {
  fs.writeFile(req.query.filename, data, () => {});
}

// TS-047: require() with a variable — dynamic module loading
function loadPlugin(pluginName: string): unknown {
  return require(pluginName);
}

// TS-048: child_process.fork() with user-controlled script path
import { fork } from "child_process";
function runScript(req: any): void {
  fork(req.query.script);
}

// TS-049: setTimeout with a variable callback — potential code injection
function scheduleTask(handler: Function): void {
  setTimeout(handler, 1000);
}

// TS-050: process.exit() with user-controlled argument — denial of service
function shutdown(req: any): void {
  process.exit(req.query.code);
}

// TS-051: DOM open redirect via window.location from request data
function redirectUser(req: any): void {
  window.location = req.query.returnUrl;
}

// TS-052: document.getElementById with user-controlled ID from request
function highlightSection(req: any): void {
  document.getElementById(req.query.section)!.classList.add("highlight");
}

// TS-053: fetch with template literal URL from request data — SSRF
async function proxyRequest(req: any): Promise<Response> {
  return fetch(`/api/data/${req.query.resource}`);
}

// TS-054: localStorage.getItem("token") used as a trusted auth value
function getAuthHeader(): string {
  const token = localStorage.getItem("token");
  return `Bearer ${token}`;
}

// TS-055: crypto.randomBytes with user-controlled size — DoS risk
function generateNonce(req: any): Buffer {
  return crypto.randomBytes(Number(req.query.size));
}

// TS-056: res.download() with user-controlled path
function downloadFile(res: any, req: any): void {
  res.download(req.query.file);
}

// TS-057: exec() with direct request variable — command injection
function runCommand(req: any): void {
  exec(req.query.cmd);
}

// TS-058: execFile() with user-controlled executable path
import { execFile } from "child_process";
function runBinary(req: any): void {
  execFile(req.query.binary, ["--safe"]);
}

// TS-059: net.createConnection with user-controlled host — raw TCP SSRF
import net from "net";
function proxyTcp(req: any): void {
  net.createConnection(req.query.port, req.query.host);
}

// TS-060: res.jsonp() with user-controlled data — JSONP callback injection
function sendJsonp(res: any, req: any): void {
  res.jsonp(req.query.data);
}

// TS-061: fs.readFileSync() with user-controlled path — synchronous path traversal
function readConfig(req: any): string {
  return fs.readFileSync(req.query.file, "utf8");
}

// TS-062: spawnSync() with user-controlled executable — synchronous shell injection
import { spawnSync } from "child_process";
function runTool(req: any): void {
  spawnSync(req.query.tool, ["--config", "default.cfg"]);
}

// TS-063: new vm.Script() with user-controlled code — VM code injection
function compileScript(req: any): void {
  const script = new vm.Script(req.query.code);
  script.runInNewContext({});
}

// TS-064: document.write() with user-controlled HTML — DOM XSS
function writeToDoc(req: any): void {
  document.write(req.query.html);
}

// TS-065: window.open() with user-controlled URL — open redirect
function openWindow(req: any): void {
  window.open(req.query.url);
}

// TS-066: jQuery .html() with user-controlled data — innerHTML injection
function renderContent(req: any): void {
  $("#output").html(req.query.content);
}

// TS-067: Object.defineProperty with user-controlled property name
function defineUserProp(req: any, obj: any): void {
  Object.defineProperty(obj, req.query.prop, { value: "x", writable: true });
}

// TS-068: crypto.createCipheriv with user-controlled algorithm
function encryptUserAlgo(req: any, key: Buffer, iv: Buffer): void {
  crypto.createCipheriv(req.query.algo, key, iv);
}

// TS-069: fs.writeFileSync with user-controlled path — write path traversal
function saveFile(req: any, data: Buffer): void {
  fs.writeFileSync(req.query.path, data);
}

// TS-070: res.set() with user-controlled header name — CRLF injection
function setHeader(res: any, req: any): void {
  res.set(req.query.headerName, "value");
}

// TS-071: new Worker() with user-controlled script URL — arbitrary code load
function launchWorker(req: any): Worker {
  return new Worker(req.query.scriptUrl);
}

// TS-072: xhr.open() with user-controlled URL — SSRF via XHR
function xhrRequest(req: any): void {
  const xhr = new XMLHttpRequest();
  xhr.open("GET", req.query.url);
}

// TS-073: res.render() with user-controlled template name — SSTI / path traversal
function renderView(res: any, req: any): void {
  res.render(req.query.template, { data: "safe" });
}

// TS-074: fs.appendFile() with user-controlled path — write path traversal
function appendLog(req: any, msg: string): void {
  fs.appendFile(req.query.logFile, msg, () => {});
}

// TS-075: crypto.pbkdf2() with user-controlled password — DoS via CPU exhaustion
function deriveKey(req: any, salt: Buffer): void {
  crypto.pbkdf2(req.query.password, salt, 100000, 64, "sha256", () => {});
}

// TS-076: .find() with user-controlled query object — NoSQL injection
async function findUser(req: any): Promise<unknown> {
  return db.collection("users").find(req.query, {});
}

// TS-077: spawn() with template literal containing request data — command injection
function runTool2(req: any): void {
  spawn(`/usr/bin/${req.query.tool}`, ["--run"]);
}

// TS-078: res.cookie() with user-controlled value — session fixation
function setCookie(res: any, req: any): void {
  res.cookie("pref", req.query.theme, { httpOnly: true });
}

// TS-079: fs.createReadStream() with user-controlled path — read path traversal
function streamFile(req: any, res: any): void {
  fs.createReadStream(req.query.file).pipe(res);
}

// TS-080: exec() with string concatenation including request data — command injection
function runCat(req: any): void {
  exec("cat " + req.query.filename);
}

// TS-081: mongoose.connect() with user-controlled URI — SSRF / credential theft
import mongoose from "mongoose";
async function connectDb(req: any): Promise<void> {
  await mongoose.connect(req.query.dbUri);
}
