/**
 * LAN server for the Safari (snarkJS) fallback of the phone kit (docs/v4/PHONE_PROTOCOL.md).
 *
 * Dependency-free (node: built-ins only). Serves a fixed allow-list of files from the repo in
 * place (no copies) and saves each posted result set to results/v4/phone/safari_<utc>.json.
 *
 *   node --import tsx mobile/safari-fallback/serve.ts [--port 8765] [--host 0.0.0.0] [--out-dir <dir>]
 *   (--out-dir only for checking the kit; real runs use the default results/v4/phone)
 *   (Node 24 also runs it directly: node mobile/safari-fallback/serve.ts)
 *
 * It prints the LAN URLs to open on the phone (same Wi-Fi network). Windows asks once whether
 * Node may accept connections on private networks; allow it for the session, then stop the
 * server (Ctrl+C) when the runs are done.
 *
 * Every response carries Cache-Control: no-store, so each page load downloads the zkey and
 * wasm again (a cold page load includes the download, timed separately by the page).
 * The server records no client address, host name or user name.
 */
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const DEFAULT_OUT_DIR = path.join(REPO_ROOT, "results", "v4", "phone");
const MAX_BODY = 4 * 1024 * 1024;
const SCHEMA = "pqid/v4-phone-safari/v1";

interface Route {
  file: string; // repo-relative
  type: string;
}

const ROUTES: Record<string, Route> = {
  "/": { file: "mobile/safari-fallback/index.html", type: "text/html; charset=utf-8" },
  "/index.html": { file: "mobile/safari-fallback/index.html", type: "text/html; charset=utf-8" },
  "/app.js": { file: "mobile/safari-fallback/app.js", type: "text/javascript; charset=utf-8" },
  "/snarkjs.min.js": { file: "node_modules/snarkjs/build/snarkjs.min.js", type: "text/javascript; charset=utf-8" },
  "/v4/circuit.wasm": { file: "circuits/build/v4/credential_auth_v4_js/credential_auth_v4.wasm", type: "application/wasm" },
  "/v4/circuit.zkey": { file: "setup/out/v4/credential_auth_v4_dev.zkey", type: "application/octet-stream" },
  "/v4/vkey.json": { file: "setup/out/v4/verification_key_dev.json", type: "application/json" },
  "/v4/input.json": { file: "mobile/inputs/v4_input.json", type: "application/json" },
  "/v4/input.meta.json": { file: "mobile/inputs/v4_input.meta.json", type: "application/json" },
};

const HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  // Cross-origin isolation only takes effect in a secure context (not plain http on a LAN IP);
  // the page records crossOriginIsolated either way.
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Resource-Policy": "same-origin",
};

function argValue(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  if (i < 0) return undefined;
  const v = process.argv[i + 1];
  if (!v || v.startsWith("--")) throw new Error(`--${name} needs a value`);
  return v;
}

function sha256File(abs: string): string {
  return createHash("sha256").update(fs.readFileSync(abs)).digest("hex");
}

function snarkjsVersion(): string | null {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "node_modules", "snarkjs", "package.json"), "utf8")) as { version?: string };
    return pkg.version ?? null;
  } catch {
    return null;
  }
}

/** Artifact hashes and sizes, computed once at start-up (served as /manifest.json). */
function buildManifest(): Record<string, unknown> {
  const pinsFile = path.join(REPO_ROOT, "setup", "pins_v4.json");
  const pins = fs.existsSync(pinsFile)
    ? (JSON.parse(fs.readFileSync(pinsFile, "utf8")) as Record<string, { path: string; sha256: string }>)
    : {};
  const pinByPath = new Map(Object.values(pins).map((p) => [p.path, p.sha256]));
  const files: Record<string, unknown> = {};
  for (const [url, r] of Object.entries(ROUTES)) {
    if (!url.startsWith("/v4/") && url !== "/snarkjs.min.js") continue;
    const abs = path.join(REPO_ROOT, r.file);
    if (!fs.existsSync(abs)) throw new Error(`${r.file} missing`);
    const sha256 = sha256File(abs);
    const pinned = pinByPath.get(r.file);
    files[url] = { path: r.file, bytes: fs.statSync(abs).size, sha256, pinMatch: pinned === undefined ? null : pinned === sha256 };
  }
  return {
    schema: "pqid/v4-phone-safari-manifest/v1",
    keyLabel: "dev",
    snarkjs: snarkjsVersion(),
    files,
    server: { node: process.versions.node, platform: process.platform, startedUtc: new Date().toISOString() },
  };
}

function compactUtc(d: Date): string {
  return d.toISOString().replace(/[-:]/g, "").replace(/\.(\d{3})Z$/, "$1Z"); // 20260927T081530123Z
}

function lanUrls(port: number): string[] {
  const out: string[] = [];
  for (const addrs of Object.values(os.networkInterfaces())) {
    for (const a of addrs ?? []) {
      if (a.family === "IPv4" && !a.internal) out.push(`http://${a.address}:${port}/`);
    }
  }
  return out;
}

function send(res: http.ServerResponse, status: number, type: string, body: string | Buffer): void {
  res.writeHead(status, { ...HEADERS, "Content-Type": type, "Content-Length": Buffer.byteLength(body) });
  res.end(body);
}

function main(): void {
  const port = Number(argValue("port") ?? "8765");
  const host = argValue("host") ?? "0.0.0.0";
  const outArg = argValue("out-dir");
  const OUT_DIR = outArg ? path.resolve(outArg) : DEFAULT_OUT_DIR;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("bad --port");
  const manifest = buildManifest();
  const manifestText = JSON.stringify(manifest, null, 2);
  for (const [url, f] of Object.entries(manifest.files as Record<string, { pinMatch: boolean | null }>)) {
    if (f.pinMatch === false) throw new Error(`${url} does not match setup/pins_v4.json; refusing to serve`);
  }

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (req.method === "GET" && url.pathname === "/manifest.json") {
      send(res, 200, "application/json", manifestText);
      return;
    }
    if (req.method === "GET") {
      const route = ROUTES[url.pathname];
      if (!route) {
        send(res, 404, "text/plain; charset=utf-8", "not found\n");
        return;
      }
      const abs = path.join(REPO_ROOT, route.file);
      const size = fs.statSync(abs).size;
      res.writeHead(200, { ...HEADERS, "Content-Type": route.type, "Content-Length": size });
      fs.createReadStream(abs).pipe(res);
      return;
    }
    if (req.method === "POST" && url.pathname === "/results") {
      const chunks: Buffer[] = [];
      let total = 0;
      let aborted = false;
      req.on("data", (c: Buffer) => {
        total += c.length;
        if (total > MAX_BODY && !aborted) {
          aborted = true;
          send(res, 413, "text/plain; charset=utf-8", "too large\n");
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on("end", () => {
        if (aborted) return;
        let body: Record<string, unknown>;
        try {
          body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
        } catch {
          send(res, 400, "text/plain; charset=utf-8", "invalid JSON\n");
          return;
        }
        if (body["schema"] !== SCHEMA || !Array.isArray(body["records"])) {
          send(res, 400, "text/plain; charset=utf-8", `expected schema ${SCHEMA} with a records array\n`);
          return;
        }
        const now = new Date();
        const file = path.join(OUT_DIR, `safari_${compactUtc(now)}.json`);
        const saved = { ...body, server: { receivedUtc: now.toISOString(), manifest } };
        fs.mkdirSync(OUT_DIR, { recursive: true });
        fs.writeFileSync(file, JSON.stringify(saved, null, 2) + "\n", { flag: "wx" });
        const relPath = outArg ? path.basename(file) : path.relative(REPO_ROOT, file).split(path.sep).join("/");
        console.log(`[serve] saved ${relPath} (${(body["records"] as unknown[]).length} record(s))`);
        send(res, 201, "application/json", JSON.stringify({ saved: relPath }));
      });
      return;
    }
    send(res, 405, "text/plain; charset=utf-8", "method not allowed\n");
  });

  server.listen(port, host, () => {
    console.log(`[serve] PQ-Identity v4 Safari fallback (dev key), snarkjs ${String(manifest["snarkjs"])}`);
    console.log(`[serve] results -> ${outArg ? "(--out-dir)" : path.relative(REPO_ROOT, OUT_DIR).split(path.sep).join("/")}/safari_<utc>.json`);
    console.log(`[serve] on this computer: http://localhost:${port}/`);
    const urls = lanUrls(port);
    if (urls.length === 0) console.log("[serve] no LAN IPv4 address found: is Wi-Fi connected?");
    for (const u of urls) console.log(`[serve] on the phone (same Wi-Fi): ${u}`);
    console.log("[serve] Ctrl+C to stop");
  });
}

main();
