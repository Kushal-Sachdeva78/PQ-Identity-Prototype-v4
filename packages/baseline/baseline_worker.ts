import fs from "node:fs";
import {
  createHash,
  createSign,
  createVerify,
  generateKeyPairSync,
  randomBytes,
} from "node:crypto";
import { execFileSync } from "node:child_process";
import pgPkg from "pg";
import { summarize, timeSyncMs, type SampleSummary } from "@pqid/common/stats";

const { Client } = pgPkg;

/**
 * M9: centralized classical baseline for Table VI — OAuth2-style bearer
 * tokens + ECDSA P-256 + a PostgreSQL-backed PII store, all MEASURED [M]
 * (the paper's baseline column was reference/analytical [A]).
 *
 * Methodology mirrors the PQC bench: N iterations (default 1000), 5 warmup,
 * mean/median/sample σ/min/max/p95.
 */
const N = Number(process.env["PQID_BASELINE_N"] ?? 1000);
const WARMUP = Number(process.env["PQID_BASELINE_WARMUP"] ?? 5);

function loop(fn: () => void): SampleSummary {
  for (let i = 0; i < WARMUP; i++) fn();
  const samples: number[] = [];
  for (let i = 0; i < N; i++) samples.push(timeSyncMs(fn));
  return summarize(samples);
}

function benchEcdsaP256(): Record<string, unknown> {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const message = randomBytes(32);

  // raw 64-byte (r,s) signatures — the paper's "~64 B" ECDSA artifact
  const signOpts = { dsaEncoding: "ieee-p1363" as const, key: privateKey };
  const verifyOpts = { dsaEncoding: "ieee-p1363" as const, key: publicKey };

  let sig: Buffer = Buffer.alloc(0);
  const signStats = loop(() => {
    const s = createSign("SHA256");
    s.update(message);
    sig = s.sign(signOpts);
  });
  const verifyStats = loop(() => {
    const v = createVerify("SHA256");
    v.update(message);
    if (!v.verify(verifyOpts, sig)) throw new Error("ECDSA verify failed");
  });
  const keygenStats = loop(() => {
    generateKeyPairSync("ec", { namedCurve: "P-256" });
  });

  return {
    keygen: keygenStats,
    sign: signStats,
    verify: verifyStats,
    sizes: {
      signatureBytes: sig.length, // 64 (ieee-p1363)
      publicKeyDerSpkiBytes: publicKey.export({ type: "spki", format: "der" }).length,
      publicKeyUncompressedPointBytes: 65,
    },
  };
}

function benchTokens(): Record<string, unknown> {
  // Opaque bearer token: 32 bytes of entropy, base64url (typical OAuth2 form)
  const opaque = randomBytes(32).toString("base64url");

  // JWT (ES256) access token — realistic claims, no PII beyond a user id
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const b64 = (o: unknown): string =>
    Buffer.from(JSON.stringify(o)).toString("base64url");
  const header = b64({ alg: "ES256", typ: "JWT" });
  const payload = b64({
    sub: "user-12345",
    aud: "https://api.example",
    iss: "https://auth.example",
    scope: "openid profile",
    iat: 1767225600,
    exp: 1767229200,
  });
  let jwt = "";
  const issueStats = loop(() => {
    const s = createSign("SHA256");
    s.update(`${header}.${payload}`);
    const sig = s.sign({ key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64url");
    jwt = `${header}.${payload}.${sig}`;
  });
  const verifyStats = loop(() => {
    const [h, p, sg] = jwt.split(".") as [string, string, string];
    const v = createVerify("SHA256");
    v.update(`${h}.${p}`);
    if (!v.verify({ key: publicKey, dsaEncoding: "ieee-p1363" }, Buffer.from(sg, "base64url"))) {
      throw new Error("JWT verify failed");
    }
  });

  return {
    opaqueTokenBytes: Buffer.byteLength(opaque),
    jwtEs256Bytes: Buffer.byteLength(jwt),
    jwtIssue: issueStats,
    jwtVerify: verifyStats,
  };
}

/** PostgreSQL host discovery: env override → 127.0.0.1 → WSL eth0 address. */
function resolvePgHost(): string {
  const env = process.env["PQID_PG_HOST"];
  if (env) return env;
  if (process.platform === "win32") {
    try {
      const ip = execFileSync("wsl", ["-u", "root", "-e", "hostname", "-I"], {
        encoding: "utf8",
      })
        .trim()
        .split(/\s+/)[0];
      if (ip) return ip; // NAT-mode WSL2: connect to the distro's eth0 directly
    } catch {
      /* fall through */
    }
  }
  return "127.0.0.1";
}

async function benchPostgres(): Promise<Record<string, unknown>> {
  const client = new Client({
    host: resolvePgHost(),
    port: Number(process.env["PQID_PG_PORT"] ?? 5432),
    user: "pqid",
    password: "pqid",
    database: "pqid_baseline",
  });
  await client.connect();
  const version = (await client.query("SELECT version()")).rows[0] as { version: string };

  await client.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      profile JSONB NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS tokens (
      token TEXT PRIMARY KEY,
      user_id INT NOT NULL REFERENCES users(id),
      expires_at TIMESTAMPTZ NOT NULL
    );
    TRUNCATE tokens, users RESTART IDENTITY CASCADE;
  `);

  const run = randomBytes(4).toString("hex");
  const profile = {
    fullName: "Synthetic User",
    dateOfBirth: "1984-01-01",
    address: "1 Synthetic Way",
    nationalId: "X1234567",
  };
  const pwHash = createHash("sha256").update("synthetic-password").digest("hex");

  // INSERT: the centralized IdP storing a full PII record per user
  const insertSamples: number[] = [];
  for (let i = 0; i < N + WARMUP; i++) {
    const t0 = process.hrtime.bigint();
    await client.query(
      "INSERT INTO users (username, email, password_hash, profile) VALUES ($1,$2,$3,$4)",
      [`user-${run}-${i}`, `user${i}@example.com`, pwHash, JSON.stringify(profile)]
    );
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    if (i >= WARMUP) insertSamples.push(ms);
  }

  // token issuance: opaque token row per session
  const tokens: string[] = [];
  for (let i = 0; i < N + WARMUP; i++) {
    const tok = randomBytes(32).toString("base64url");
    tokens.push(tok);
    await client.query(
      "INSERT INTO tokens (token, user_id, expires_at) VALUES ($1,$2, now() + interval '1 hour')",
      [tok, (i % N) + 1]
    );
  }

  // SELECT: per-authentication token introspection + user fetch (the
  // baseline's verifier-side work)
  const selectSamples: number[] = [];
  for (let i = 0; i < N + WARMUP; i++) {
    const tok = tokens[i % tokens.length] as string;
    const t0 = process.hrtime.bigint();
    const res = await client.query(
      "SELECT u.id, u.username, u.profile FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.token = $1 AND t.expires_at > now()",
      [tok]
    );
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    if (res.rowCount !== 1) throw new Error("token lookup failed");
    if (i >= WARMUP) selectSamples.push(ms);
  }

  const storage = await client.query(
    "SELECT pg_column_size(u.*) AS user_row, pg_column_size(t.*) AS token_row FROM users u, tokens t LIMIT 1"
  );
  await client.end();

  return {
    serverVersion: version.version,
    insert: summarize(insertSamples),
    tokenAuthSelect: summarize(selectSamples),
    storage: storage.rows[0] as Record<string, unknown>,
    note: "localhost TCP from Windows host into WSL2 PostgreSQL (single round-trip per query)",
  };
}

async function main(): Promise<void> {
  const outFile = process.env["PQID_RUN_OUT"];
  if (!outFile) throw new Error("PQID_RUN_OUT required (run via bench_baseline.ts)");
  console.log(`[baseline:worker] N=${N}, warmup=${WARMUP}`);
  const ecdsa = benchEcdsaP256();
  const tokens = benchTokens();
  const postgres = await benchPostgres();
  fs.writeFileSync(outFile, JSON.stringify({ config: { n: N, warmup: WARMUP }, ecdsaP256: ecdsa, oauth2Tokens: tokens, postgres }));
  process.exit(0);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
