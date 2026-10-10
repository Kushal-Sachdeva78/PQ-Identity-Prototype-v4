import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
const out = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(out, '../../..');
const sourceFile = path.join(root, 'packages/v4/src/wallet.ts');
const source = fs.readFileSync(sourceFile, 'utf8');
const sha = s => createHash('sha256').update(s).digest('hex');
let copy = source.replace(/from "\.\/([^"\n]+)\.ts"/g, 'from "../../../packages/v4/src/$1.ts"');
const state = '  /** Dates the wallet has committed to answering (B5 CIR-1): at most one date per 2 x skew window. */\n  private readonly dateLog: Array<{ date: number; atSec: number }> = [];\n';
if (!copy.includes(state)) throw new Error('source date-state declaration changed');
copy = copy.replace(state, '');
const start = copy.indexOf('    const skew = this.cfg.skewSec ?? WALLET_CLOCK_SKEW_SEC;');
const end = copy.indexOf('    this.check("thresholdStandard",', start);
if (start < 0 || end < 0) throw new Error('source date-check block changed');
const removed = copy.slice(start, end);
const replacement = '    this.check("dateCurrent", statelessDateAllowed(now, request.policy.today), "stateless policy: date unavailable");\n';
copy = 'import { statelessDateAllowed } from "./date_policy.ts";\n' + copy.slice(0, start) + replacement + copy.slice(end);
const writeOnce = (name, text) => { const p = path.join(out, name); if (fs.existsSync(p)) { if (fs.readFileSync(p, 'utf8') !== text) throw new Error('refusing overwrite: '+name); } else fs.writeFileSync(p, text); };
writeOnce('wallet_stateless_v1.ts', copy);
writeOnce('variant_change.json', JSON.stringify({ schema:'privacy-variant-diff/v1', source:'packages/v4/src/wallet.ts', originalSha256:sha(source), variantSha256:sha(copy), importRelocation:'./<module>.ts -> ../../../packages/v4/src/<module>.ts', removedState:state, removedDateBlock:removed, addedDateBlock:replacement, policySource:'date_policy.ts', policySha256:sha(fs.readFileSync(path.join(out,'date_policy.ts'))) },null,2)+'\n');
const paths = {};
for (const name of fs.readdirSync(path.join(root,'packages'))) {
 const pkgFile=path.join(root,'packages',name,'package.json'); if (!fs.existsSync(pkgFile)) continue;
 const pkg=JSON.parse(fs.readFileSync(pkgFile,'utf8')); if (!pkg.name) continue;
 if (pkg.exports && typeof pkg.exports === 'object') for (const [key,value] of Object.entries(pkg.exports)) { if (typeof value==='string') paths[pkg.name+(key==='.'?'':key.slice(1))]=['packages/'+name+'/'+value.replace(/^\.\//,'')]; }
 else if (typeof pkg.exports === 'string') paths[pkg.name]=['packages/'+name+'/'+pkg.exports.replace(/^\.\//,'')];
 if (!paths[pkg.name] && fs.existsSync(path.join(root,'packages',name,'src/index.ts'))) paths[pkg.name]=['packages/'+name+'/src/index.ts'];
}
writeOnce('tsconfig.json',JSON.stringify({extends:'../../../tsconfig.json',compilerOptions:{baseUrl:'../../..',paths},include:['*.ts','../../../types/**/*.d.ts'],exclude:[]},null,2)+'\n');
writeOnce('preregistration.json',JSON.stringify({schema:'privacy-preregistration/v1', preparedUtc:new Date().toISOString(), protocolFile:'PROTOCOL.md',protocolSha256:sha(fs.readFileSync(path.join(out,'PROTOCOL.md'))),variantSha256:sha(copy),policySha256:sha(fs.readFileSync(path.join(out,'date_policy.ts'))), preparedBeforeAnyMeasurement:true},null,2)+'\n');
console.log('Prepared protocol hash, isolated variant and local import map.');
