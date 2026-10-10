import fs from "node:fs";
import path from "node:path";
import { Readable } from "node:stream";
import { finished } from "node:stream/promises";
import { PTAU_FILE, PTAU_DIR } from "@pqid/common/paths";
import { sha256File } from "@pqid/common/hash";
import { verifyOrPin } from "./pins.ts";

const PTAU_URL =
  "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_15.ptau";

async function main(): Promise<void> {
  fs.mkdirSync(PTAU_DIR, { recursive: true });
  if (!fs.existsSync(PTAU_FILE)) {
    console.log(`[ptau] downloading ${PTAU_URL}`);
    const res = await fetch(PTAU_URL);
    if (!res.ok || !res.body) {
      throw new Error(`ptau download failed: HTTP ${res.status}`);
    }
    const tmp = PTAU_FILE + ".part";
    const ws = fs.createWriteStream(tmp);
    await finished(Readable.fromWeb(res.body as never).pipe(ws));
    fs.renameSync(tmp, PTAU_FILE);
  } else {
    console.log(`[ptau] already present: ${path.basename(PTAU_FILE)}`);
  }
  const digest = sha256File(PTAU_FILE);
  verifyOrPin("powersOfTau28_hez_final_15.ptau", digest, {
    source: PTAU_URL,
    note: "Hermez phase-1 powers of tau, 2^15; established public ceremony [A]",
  });
  console.log(
    `[ptau] size ${(fs.statSync(PTAU_FILE).size / 1024 / 1024).toFixed(1)} MiB, sha256 ${digest}`
  );
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
