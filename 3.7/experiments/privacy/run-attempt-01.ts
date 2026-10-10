import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { World } from '@pqid/v4/world';
import { HolderWalletV4 } from '@pqid/v4/wallet';
import { HolderWalletV4 as StatelessWallet } from './wallet_stateless_v1.ts';
import { DEFAULT_TYPE_ID } from '@pqid/v4/constants';
import { utcDateOf, unixOfUtcDate } from '@pqid/v4/dates';
import { revokeCredentialV4 } from '@pqid/v4/issuer';
import type { VerifierV4 } from '@pqid/v4/verifier';
import { statelessDateAllowed } from './date_policy.ts';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../../..');
const MIDNIGHT = unixOfUtcDate(20261010);
const TODAY = 20261010, PREVIOUS = 20261009, TOMORROW = 20261011;
const sha = (s: string | Buffer) => createHash('sha256').update(s).digest('hex');
const scrub = (s: string) => s.replaceAll(ROOT, '<repository>').replaceAll(ROOT.replaceAll('\\','/'), '<repository>');
type Policy = 'shipped' | 'stateless-v1';
type Wallet = HolderWalletV4 | StatelessWallet;
type Event = { id: string; policy: Policy; holder: string; role: string; offsetSec: number; requestedDate: number; threshold: number; outcome: string; expected: string; expectationMet: boolean; message?: string; messageUtf8Bytes?: number; replyEmitted: boolean; verifierAccepted?: boolean; failedChecks?: string[]; [key: string]: unknown };
const policies: Policy[] = ['shipped','stateless-v1'];
let runDir = '';
let world: World | undefined;
const events: Event[] = [];
const pairs: Record<string, unknown>[] = [];
const holders = new Map<string, Wallet>();
let before: Record<string,string> = {};
const collectFiles = (dir: string): string[] => fs.readdirSync(dir, {withFileTypes:true}).flatMap(e => e.isDirectory() ? collectFiles(path.join(dir,e.name)) : [path.join(dir,e.name)]);
function sourceHashes() {
 const files = collectFiles(path.join(ROOT,'packages')).filter(p=>p.endsWith('.ts')||p.endsWith('package.json'));
 for (const p of ['setup/pins_v4.json','setup/out/v4/credential_auth_v4_dev.zkey','setup/out/v4/verification_key_dev.json','circuits/build/v4/credential_auth_v4_js/credential_auth_v4.wasm','circuits/build/v4/credential_auth_v4.r1cs','onchain/contracts/v4/RegistriesV4.sol']) files.push(path.join(ROOT,p));
 return Object.fromEntries(files.map(p=>[path.relative(ROOT,p).replaceAll('\\','/'),sha(fs.readFileSync(p))]));
}
const save = (name: string, value: unknown) => fs.writeFileSync(path.join(runDir,name),JSON.stringify(value,null,2)+'\n');
async function freePort(): Promise<number> { return new Promise((resolve,reject)=>{ const server=net.createServer(); server.once('error',reject); server.listen(0,'127.0.0.1',()=>{ const p=(server.address() as net.AddressInfo).port; server.close(e=>e?reject(e):resolve(p)); }); }); }
async function perform(policy: Policy, holder: string, verifier: VerifierV4, role: string, offsetSec: number, requestedDate: number, threshold: number, expected: string, typeId=DEFAULT_TYPE_ID): Promise<Event> {
 if (!world) throw new Error('world not initialized');
 const wallet=holders.get(`${policy}/${holder}`); if (!wallet) throw new Error('missing holder '+holder);
 world.clock.set(MIDNIGHT+offsetSec);
 const req = await verifier.newRequest({predicate:'age_gte',threshold,typeId,today:requestedDate===20261301?TODAY:requestedDate});
 if (requestedDate===20261301) req.policy.today=requestedDate;
 const event:Event = {id:`${policy}/${holder}/${role}/${events.length+1}`,policy,holder,role,offsetSec,requestedDate,threshold,typeId,expected,outcome:'unrecorded',expectationMet:false,replyEmitted:false,clockUtc:new Date((MIDNIGHT+offsetSec)*1000).toISOString(),label:'[M, dev]',request:req};
 try {
  const {reply,presentation} = await wallet.present(req, {callerOrigin:verifier.opts.identity.origin});
  const decision=await verifier.verifyReply(reply);
  event.outcome = decision.accepted?'accepted':'verifier-rejected';
  event.replyEmitted=true; event.verifierAccepted=decision.accepted; event.failedChecks=decision.failedChecks;
  event.replyUtf8Bytes=Buffer.byteLength(JSON.stringify(reply)); event.replySha256=sha(JSON.stringify(reply));
  event.proof= presentation.proof; event.publicSignals=presentation.publicSignals;
  event.presentationSha256=sha(JSON.stringify(presentation)); event.verifierDecision=decision;
 } catch (e: unknown) {
  const err=e as {check?:string;message?:string;name?:string};
  event.outcome=err.check?`refused:${err.check}`:`error:${err.name??'unknown'}`;
  event.message=scrub(err.message??String(e)); event.messageUtf8Bytes=Buffer.byteLength(event.message);
 }
 event.expectationMet=event.outcome===expected;
 events.push(event); fs.appendFileSync(path.join(runDir,'events.jsonl'),JSON.stringify(event)+'\n');
 console.log(`${event.id}: ${event.outcome}${event.expectationMet?'':' [UNEXPECTED expected '+expected+']'}`);
 return event;
}
const observation = (e: Event) => ({reply:e.replyEmitted,check:e.outcome,message:e.message??null});

async function main() {
 if (fs.existsSync(path.join(ROOT,'results/v4/bench/RUNNING'))) throw new Error('benchmark RUNNING marker exists');
 const prereg=JSON.parse(fs.readFileSync(path.join(HERE,'preregistration.json'),'utf8'));
 if(prereg.protocolSha256!==sha(fs.readFileSync(path.join(HERE,'PROTOCOL.md')))) throw new Error('protocol hash changed');
 if(prereg.variantSha256!==sha(fs.readFileSync(path.join(HERE,'wallet_stateless_v1.ts')))) throw new Error('variant hash changed');
 if(prereg.policySha256!==sha(fs.readFileSync(path.join(HERE,'date_policy.ts')))) throw new Error('policy hash changed');
 let n=1; while(fs.existsSync(path.join(HERE,`run-${String(n).padStart(2,'0')}`))) n++;
 runDir=path.join(HERE,`run-${String(n).padStart(2,'0')}`); fs.mkdirSync(runDir);
 before=sourceHashes(); save('sources_before.json',before);
 save('run_start.json',{schema:'privacy-run/v1',startedUtc:new Date().toISOString(),preregistration:prereg,runnerSha256:sha(fs.readFileSync(fileURLToPath(import.meta.url))),environment:{platform:process.platform,arch:process.arch,node:process.version,openssl:process.versions.openssl,cpu:os.cpus()[0]?.model},label:'[M, dev]',network:'local Anvil, same host',timingMeasurements:false,selection:'internally selected reviewer-informed tests, not independent testing'});
 world=await World.create({port:await freePort()}); world.clock.set(MIDNIGHT-3600); await world.syncChainTime();
 const issuer=await world.addIssuer('privacy-fixture');
 const A=await world.addVerifier('privacy-reference'); const B=await world.addVerifier('privacy-challenge');
 const boundaryIds=['b-301','b-300','b-1','b0','b299','b300','previous299','previous300','futureBefore','gap601','gap600','threshold17','predicate65','unknownType','revoked','birthday','invalidDate'];
 for(const policy of policies) {
  const ids=[...Array.from({length:6},(_,i)=>[`p${i+1}-0`,`p${i+1}-1`]).flat(),...boundaryIds];
  for(const id of ids) {
   const cfg={ledger:world.ledger,clock:world.clock,pinnedGovernancePk:world.governance.pk,originBinding:true};
   const wallet=policy==='shipped'?await HolderWalletV4.create(cfg):await StatelessWallet.create(cfg);
   holders.set(`${policy}/${id}`,wallet);
   const vc=await world.issue(issuer,wallet as unknown as HolderWalletV4,{birthDate:id==='birthday'?20081010:20000101,expiryDate:20261231});
   if(id==='revoked') revokeCredentialV4(issuer,vc.credID);
  }
 }
 await world.publishEpoch(issuer);
 for(const policy of policies) {
  for(let p=1;p<=6;p++) {
   const pId=`p${p}`;
   const referenceIndices=p===1?[]:(p===2||p===5?[0,1]:[0]);
   const referenceOffset=(p===4||p===5)?3600:-301;
   const referenceDate=(p===4||p===5)?TODAY:PREVIOUS;
   for(const i of referenceIndices) await perform(policy,`${pId}-${i}`,A,'reference',referenceOffset,referenceDate,p===6?65:18,p===6?'refused:predicateHolds':'accepted');
   const challenges:Event[]=[];
   for(let i=0;i<2;i++) {
    const messageProbe=p===4||p===5;
    const expected=policy==='stateless-v1'||messageProbe||p===2||((p===3||p===6)&&i===0)?'refused:dateCurrent':'accepted';
    challenges.push(await perform(policy,`${pId}-${i}`,B,'challenge',messageProbe?3601:60,messageProbe?TOMORROW:TODAY,18,expected));
   }
   pairs.push({id:`${policy}/${pId}`,policy,scenario:p,referenceHolderIndices:referenceIndices,challengeIds:challenges.map(e=>e.id),replyPresenceDiffers:challenges[0]!.replyEmitted!==challenges[1]!.replyEmitted,checkDiffers:challenges[0]!.outcome!==challenges[1]!.outcome,messageObservationDiffers:JSON.stringify(observation(challenges[0]!))!==JSON.stringify(observation(challenges[1]!)),observations:challenges.map(observation),label:'[M, dev] deterministic pair contrast; not a population estimate'});
  }
  for(const offset of [-301,-300,-1,0,299,300]) await perform(policy,`b${offset}`,B,'control',offset,offset<0?PREVIOUS:TODAY,18,policy==='stateless-v1'&&offset!==-301&&offset!==300?'refused:dateCurrent':'accepted');
  await perform(policy,'previous299',B,'control',299,PREVIOUS,18,policy==='shipped'?'accepted':'refused:dateCurrent');
  await perform(policy,'previous300',B,'control',300,PREVIOUS,18,'refused:dateCurrent');
  await perform(policy,'futureBefore',B,'control',-301,TODAY,18,'refused:dateCurrent');
  for(const gap of [600,601]) {
   await perform(policy,`gap${gap}`,A,'reference',-301,PREVIOUS,18,'accepted');
   await perform(policy,`gap${gap}`,B,'control',gap-301,TODAY,18,gap===601?'accepted':'refused:dateCurrent');
  }
  await perform(policy,'threshold17',B,'control',3600,TODAY,17,'refused:thresholdStandard');
  await perform(policy,'predicate65',B,'control',3600,TODAY,65,'refused:predicateHolds');
  await perform(policy,'unknownType',B,'control',3600,TODAY,18,'refused:typeAllowed','pqid:type:unavailable');
  await perform(policy,'revoked',B,'control',3600,TODAY,18,'refused:anchorMatches');
  await perform(policy,'birthday',A,'reference',-301,PREVIOUS,18,'refused:predicateHolds');
  await perform(policy,'birthday',B,'control',300,TODAY,18,'accepted');
  await perform(policy,'invalidDate',B,'control',3600,20261301,18,'refused:requestShape');
 }
 let eligible=0; for(let second=0;second<86400;second++) if(statelessDateAllowed(MIDNIGHT+second,TODAY)) eligible++;
 const after=sourceHashes(); save('sources_after.json',after);
 const sourceChanges=Object.keys(before).filter(p=>before[p]!==after[p]);
 const mismatches=events.filter(e=>!e.expectationMet).map(e=>({id:e.id,expected:e.expected,actual:e.outcome}));
 const pairExpectationFailures=pairs.filter(p=>p.messageObservationDiffers!==(p.policy==='shipped'&&[3,4,6].includes(p.scenario as number))).map(p=>p.id);
 const report={schema:'privacy-results/v1',finishedUtc:new Date().toISOString(),protocolSha256:prereg.protocolSha256,runLabel:'[M, dev], controlled-clock local experiment; no timing inference',calls:events.length,expectedOutcomes:events.length-mismatches.length,unexpectedOutcomes:mismatches,sourceChanges,pairExpectationFailures,allPrespecifiedChecksPassed:!mismatches.length&&!sourceChanges.length&&!pairExpectationFailures.length&&eligible===85800,acceptedReplies:events.filter(e=>e.verifierAccepted).length,refusals:events.filter(e=>e.outcome.startsWith('refused:')).length,pairs,availability:{label:'[S] enumeration of configured integer-second date policy, not measured uptime',secondsPerDay:86400,eligibleSeconds:eligible,blackoutSeconds:86400-eligible,blackoutPercent:(86400-eligible)/86400*100,lastAnswerOffset:-301,firstAnswerOffset:300,minimumCrossDateGapSec:601},limitations:['Single local fixture and synchronized injected clocks.','No independent tester; cases selected internally from reviewer feedback and source inspection.','No timing or browser/API transport measurements; message disclosure follows the documented conservative caller model.','Experimental variant only, not installed; no changed snapshot C2 verdict or proof of unlinkability.','Other refusal-kind, clock-offset, configuration and blob-sync channels remain.','Existing dev key and classical Groth16 soundness assumptions remain.']};
 save('results.json',report);
 console.log(JSON.stringify({run:path.basename(runDir),calls:report.calls,unexpected:mismatches.length,allPrespecifiedChecksPassed:report.allPrespecifiedChecksPassed,acceptedReplies:report.acceptedReplies}));
 world.stop(); world=undefined;
 process.exitCode=report.allPrespecifiedChecksPassed?0:2;
}
main().catch(e=>{
 const failure={finishedUtc:new Date().toISOString(),status:'failed-attempt',error:scrub((e as Error).message),callsCompleted:events.length};
 if(runDir) {save('failure.json',failure); save('partial_pairs.json',pairs); if(Object.keys(before).length) save('sources_after_failure.json',sourceHashes());}
 console.error(JSON.stringify(failure)); process.exitCode=1;
}).finally(()=>{world?.stop(); setTimeout(()=>process.exit(process.exitCode??0),200);});
