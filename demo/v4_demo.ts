import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { REPO_ROOT } from "@pqid/common/paths";
import { World } from "@pqid/v4/world";
import { revokeCredentialV4 } from "@pqid/v4/issuer";
import { MIN_ANCHOR_INTERVAL_SEC, DEFAULT_TYPE_ID } from "@pqid/v4/constants";
import { KEY_LABEL_V4 } from "@pqid/v4/paths";
import { walletSealReply } from "@pqid/v4/session";
import { circuitRoute, heldOf } from "../harness/v4/suite_lib.ts";

/**
 * Offline v4 demo (TASKS G). One command, local only (Anvil on 127.0.0.1, no network):
 *   npx tsx demo/v4_demo.ts [--pace SECONDS] [--out FILE]
 *
 * Steps: governance, issuer and verifier set up on a local chain; two holders get
 * credentials; an adult proves age >= 18 (accepted); a minor's honest wallet refuses; a
 * malicious wallet with a forged birth date cannot satisfy the circuit; a captured reply is
 * replayed (rejected); the adult's credential is revoked and, after the next epoch, the
 * adult can no longer authenticate. Every line printed is program output (facts only);
 * the transcript goes to demo/out/transcript.txt for the recorded fallback
 * (demo/record_mp4.sh). The v4 key is the dev key.
 */
function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
const PACE = Number(arg("--pace") ?? 0);
const OUT = path.resolve(arg("--out") ?? path.join(REPO_ROOT, "demo", "out", "transcript.txt"));
const lines: string[] = [];
const t0 = Date.now();
function say(s = ""): void {
  const stamp = s ? `[${((Date.now() - t0) / 1000).toFixed(1).padStart(5)} s] ` : "";
  lines.push(stamp + s);
  console.log(stamp + s);
}
const pause = () => new Promise((r) => setTimeout(r, PACE * 1000));
const yearsBefore = (date: number, years: number) => date - years * 10000;

async function main(): Promise<void> {
  say(`PQ-Identity v4 demo (key: ${KEY_LABEL_V4}; local chain only)`);
  say("1. Local chain, v4 registries and a governance ML-DSA-44 key");
  const world = await World.create({ port: 8580 });
  try {
    await pause();
    say("2. Issuer: ML-DSA-44 key, DID registered with proof of possession, accredited by governance");
    const issuer = await world.addIssuer("demo-issuer");
    say(`   issuer DID ${issuer.did.slice(0, 24)}...`);
    say("3. Verifier: DID registered, ML-KEM-768 key statement published");
    const V = await world.addVerifier("venue");
    await pause();
    say("4. Two holders receive credentials (birth date, expiry and type committed in the leaf)");
    const adult = await world.addHolder();
    const minor = await world.addHolder();
    const today = world.today;
    const vcAdult = await world.issue(issuer, adult, { birthDate: 19900510 });
    const vcMinor = await world.issue(issuer, minor, { birthDate: yearsBefore(today, 16) });
    await world.publishEpoch(issuer);
    say(`   epoch anchored; today ${today}`);
    await pause();

    const policy = { predicate: "age_gte" as const, threshold: 18, typeId: DEFAULT_TYPE_ID };
    say("5. Adult proves age >= 18 over an ML-KEM session");
    const req = await V.newRequest(policy);
    const { reply } = await adult.present(req, { callerOrigin: V.opts.identity.origin });
    const d1 = await V.verifyReply(reply);
    // No timings on screen: performance numbers come only from the Phase D protocol.
    say(`   wallet produced a Groth16 proof; verifier: ${d1.accepted ? "ACCEPTED" : `rejected (${d1.failedChecks.join(", ")})`}`);
    await pause();

    say("6. Minor asks the honest wallet for the same proof");
    try {
      await minor.present(await V.newRequest(policy), { callerOrigin: V.opts.identity.origin });
      say("   unexpected: the wallet produced a proof");
    } catch (e) {
      say(`   ${(e as Error).message.split("\n")[0]}`);
    }
    await pause();

    say("7. Malicious wallet: minor's genuine credential path with a forged birth date 1990-01-01");
    const forged = await circuitRoute(world, V, await V.newRequest(policy), heldOf(minor, issuer, vcMinor), { credential: { birthDate: 19900101 } });
    const broken = Object.keys((forged as { r1cs?: { byGroup: Record<string, number> } }).r1cs?.byGroup ?? {});
    say(`   verifier: ${forged.accepted ? "ACCEPTED" : "rejected"}; violated constraint groups: ${broken.join(", ") || "none"}`);
    await pause();

    say("8. A captured reply is sent again");
    const d2 = await V.verifyReply(reply);
    say(`   verifier: ${d2.accepted ? "ACCEPTED" : `rejected (${d2.failedChecks.join(", ")})`}`);
    await pause();

    say("9. Issuer revokes the adult's credential; next epoch anchored after the minimum interval");
    revokeCredentialV4(issuer, vcAdult.credID);
    await world.advance(MIN_ANCHOR_INTERVAL_SEC + 1);
    await world.publishEpoch(issuer);
    try {
      const again = await adult.present(await V.newRequest(policy), { callerOrigin: V.opts.identity.origin });
      const d3 = await V.verifyReply(again.reply);
      say(`   verifier: ${d3.accepted ? "ACCEPTED" : `rejected (${d3.failedChecks.join(", ")})`}`);
    } catch (e) {
      say(`   wallet cannot present: ${(e as Error).message.split("\n")[0]}`);
    }
    void walletSealReply;
    say("Done.");
  } finally {
    world.stop();
  }
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, lines.join("\n") + "\n");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(
    () => process.exit(0),
    (e: unknown) => {
      console.error(e);
      process.exit(1);
    }
  );
}
