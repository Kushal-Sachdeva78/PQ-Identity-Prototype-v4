/* global snarkjs, document, window, navigator, performance, location, setTimeout, TextEncoder, URLSearchParams */
// PQ-Identity v4 Safari fallback: snarkJS 0.7.4 proving in the phone's browser
// (docs/v4/PHONE_PROTOCOL.md, Safari path). Served by mobile/safari-fallback/serve.ts.
//
// Definitions written into every result:
//   cold   = the first proof after this page loads (a reload or a new tab starts a new page;
//            the browser's web-content process and its caches may survive, so this is a
//            page-level cold start, not a process-level one);
//   warmup = later proofs that are not analysed; warm = later proofs on the same page.
// Phases (same calls as docs/v4/BENCH_PROTOCOL.md "What is timed", in the browser):
//   witness = snarkjs.wtns.calculate(input, wasm bytes, in-memory wtns)
//   prove   = snarkjs.groth16.prove(zkey bytes, in-memory wtns)
//   verify  = snarkjs.groth16.verify(vkey, publicSignals, proof)   (outside the energy window)
// The zkey, wasm, vkey and input are downloaded once per page load and timed separately
// (downloadMs); proofs read them from memory. Safari has no performance.memory (a Chrome-only
// API) and no battery or thermal API, so memory, battery and thermal are not recorded here.
"use strict";

const SCHEMA = "pqid/v4-phone-safari/v1";
const $ = (id) => document.getElementById(id);

const state = {
  pageLoadUtc: new Date().toISOString(),
  sessionId: randomHex(16),
  proofs: 0,
  running: false,
  hiddenDuringRun: false,
  art: null,
  session: null,
};

function randomHex(nBytes) {
  const b = new Uint8Array(nBytes);
  window.crypto.getRandomValues(b); // available in insecure contexts too
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function log(line) {
  $("log").textContent = line + "\n" + $("log").textContent;
}

function status(text) {
  $("status").textContent = text;
}

function sleep(sec) {
  return new Promise((r) => setTimeout(r, Math.max(0, sec) * 1000));
}

// ------------------------------------------------------------ settings (form <-> URL)
const NUM_FIELDS = ["settle", "warmup", "n", "gap", "pre", "post", "runs", "idle"];
const params = new URLSearchParams(location.search);
// A cold campaign (mode=cold, auto reload) keeps one campaign id across its page loads.
const campaignId = params.get("campaign") || (params.get("mode") === "cold" ? state.sessionId.slice(0, 8) : null);
const campaignRun = params.get("mode") === "cold" ? Number(params.get("i") || "1") : null;

function readSettings() {
  const s = {};
  for (const f of NUM_FIELDS) s[f] = Number($(f).value);
  s.flash = $("flashOn").checked;
  return s;
}

function applyParams() {
  for (const f of NUM_FIELDS) if (params.has(f)) $(f).value = params.get(f);
  if (params.get("flash") === "1") $("flashOn").checked = true;
}

// ------------------------------------------------------------ environment
function navigationType() {
  const nav = performance.getEntriesByType && performance.getEntriesByType("navigation")[0];
  return nav ? nav.type : "unknown";
}

function environment() {
  return {
    userAgent: navigator.userAgent,
    platform: navigator.platform || null,
    hardwareConcurrency: navigator.hardwareConcurrency || null,
    deviceMemory: navigator.deviceMemory === undefined ? null : navigator.deviceMemory,
    crossOriginIsolated: window.crossOriginIsolated === true,
    isSecureContext: window.isSecureContext === true,
    performanceMemoryAvailable: typeof performance.memory !== "undefined",
    measureUserAgentSpecificMemoryAvailable: typeof performance.measureUserAgentSpecificMemory === "function",
    wakeLockApi: "wakeLock" in navigator,
    screen: { width: window.screen.width, height: window.screen.height, devicePixelRatio: window.devicePixelRatio },
    navigationType: navigationType(),
  };
}

let wakeLockState = "not requested";
async function holdWakeLock() {
  if (!("wakeLock" in navigator)) {
    wakeLockState = "unavailable (needs a secure context; set Auto-Lock to Never)";
    return;
  }
  try {
    await navigator.wakeLock.request("screen");
    wakeLockState = "held";
  } catch (e) {
    wakeLockState = "failed: " + e;
  }
}

document.addEventListener("visibilitychange", () => {
  if (state.running && document.visibilityState !== "visible") state.hiddenDuringRun = true;
});

// ------------------------------------------------------------ artifacts
async function fetchTimed(url, kind) {
  const t0 = performance.now();
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  const value = kind === "json" ? await res.json() : new Uint8Array(await res.arrayBuffer());
  return { value, ms: performance.now() - t0 };
}

async function loadArtifacts() {
  status("Downloading circuit, key and input...");
  const manifest = (await fetchTimed("manifest.json", "json")).value;
  const meta = await fetchTimed("v4/input.meta.json", "json");
  const input = await fetchTimed("v4/input.json", "json");
  const vkey = await fetchTimed("v4/vkey.json", "json");
  const wasm = await fetchTimed("v4/circuit.wasm", "bytes");
  const zkey = await fetchTimed("v4/circuit.zkey", "bytes");
  const files = manifest.files;
  const sizesMatch = wasm.value.length === files["/v4/circuit.wasm"].bytes && zkey.value.length === files["/v4/circuit.zkey"].bytes;
  return {
    manifest,
    meta: meta.value,
    input: input.value,
    vkey: vkey.value,
    wasm: wasm.value,
    zkey: zkey.value,
    download: {
      wasmMs: wasm.ms,
      zkeyMs: zkey.ms,
      vkeyMs: vkey.ms,
      inputMs: input.ms,
      metaMs: meta.ms,
      wasmBytes: wasm.value.length,
      zkeyBytes: zkey.value.length,
      sizesMatchManifest: sizesMatch,
      note: "HTTP over the LAN from serve.ts, Cache-Control: no-store, uncompressed",
    },
  };
}

function newSession(settings) {
  const a = state.art;
  return {
    schema: SCHEMA,
    path: "safari-snarkjs",
    label: "[M] snarkJS in the browser named in env.userAgent (dev key); device values [VERIFY] against the device used",
    keyLabel: "dev",
    campaignId,
    campaignRun,
    sessionId: state.sessionId,
    pageLoadUtc: state.pageLoadUtc,
    env: environment(),
    wakeLock: wakeLockState,
    artifacts: {
      zkeySha256: a.manifest.files["/v4/circuit.zkey"].sha256,
      wasmSha256: a.manifest.files["/v4/circuit.wasm"].sha256,
      inputSha256: a.meta.inputSha256,
      expectedPublicSignalsSha256: a.meta.publicSignalsSha256,
      snarkjs: a.manifest.snarkjs,
    },
    download: a.download,
    protocol: {
      cold: "first proof after the page loads (page-level cold start)",
      warm: "later proofs on the same page, after `warmup` unanalysed proofs",
      settings,
    },
    records: [],
    notes: [],
  };
}

// ------------------------------------------------------------ one proof
async function flashMarker(markers, settings) {
  if (!settings.flash) return;
  $("flash").style.display = "block";
  markers.push({ event: "flash_on", utcMs: Date.now(), perfMs: performance.now() });
  await sleep(0.3);
  $("flash").style.display = "none";
  markers.push({ event: "flash_off", utcMs: Date.now(), perfMs: performance.now() });
}

async function oneProof(kind, settings) {
  const a = state.art;
  const markers = [];
  const mark = (event) => markers.push({ event, utcMs: Date.now(), perfMs: performance.now() });
  const rec = {
    index: ++state.proofs,
    kind,
    startUtc: new Date().toISOString(),
    sincePageLoadMs: performance.now(),
    visibleAtStart: document.visibilityState === "visible",
  };
  state.hiddenDuringRun = document.visibilityState !== "visible";
  if (settings.pre > 0) {
    mark("pre_idle_start");
    await sleep(settings.pre);
  }
  await flashMarker(markers, settings);
  try {
    mark("proof_start");
    const t0 = performance.now();
    const wtns = { type: "mem" };
    await snarkjs.wtns.calculate(a.input, a.wasm, wtns);
    const t1 = performance.now();
    const { proof, publicSignals } = await snarkjs.groth16.prove(a.zkey, wtns);
    const t2 = performance.now();
    mark("proof_end");
    rec.witnessMs = t1 - t0;
    rec.proveMs = t2 - t1;
    rec.wpMs = t2 - t0;
    await flashMarker(markers, settings);
    if (settings.post > 0) {
      await sleep(settings.post);
      mark("post_idle_end");
    }
    const v0 = performance.now();
    rec.verified = await snarkjs.groth16.verify(a.vkey, publicSignals, proof);
    rec.verifyMs = performance.now() - v0;
    rec.publicSignalsMatch = JSON.stringify(publicSignals) === JSON.stringify(a.meta.publicSignals);
    rec.proofJsonBytes = new TextEncoder().encode(JSON.stringify(proof)).length;
  } catch (e) {
    rec.error = String(e && e.stack ? e.stack : e);
  }
  rec.hiddenDuringRun = state.hiddenDuringRun;
  rec.visibleAtEnd = document.visibilityState === "visible";
  rec.memory = { performanceMemory: null, note: "Safari does not expose performance.memory" };
  rec.markers = markers;
  state.session.records.push(rec);
  const line = rec.error
    ? `#${rec.index} ${kind}: ERROR ${rec.error.split("\n")[0]}`
    : `#${rec.index} ${kind}: witness ${rec.witnessMs.toFixed(0)} ms, prove ${rec.proveMs.toFixed(0)} ms, verify ${rec.verifyMs.toFixed(0)} ms, ${rec.verified && rec.publicSignalsMatch ? "verified" : "NOT verified"}`;
  log(line);
  return rec;
}

// ------------------------------------------------------------ posting
async function postResults() {
  if (!state.session || state.session.records.length === 0) return null;
  state.session.postedUtc = new Date().toISOString();
  try {
    const res = await fetch("results", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(state.session),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    const j = await res.json();
    log(`posted -> ${j.saved}`);
    return j.saved;
  } catch (e) {
    log(`POST failed (${e}); press "Post results again"`);
    return null;
  }
}

// ------------------------------------------------------------ runs
function setButtons(disabled) {
  for (const id of ["btnCold", "btnWarm", "btnPost"]) $(id).disabled = disabled;
}

async function runCold() {
  const settings = readSettings();
  if (state.proofs > 0) {
    status("A proof already ran on this page: reload for another cold proof.");
    return;
  }
  state.running = true;
  setButtons(true);
  if (!state.session) state.session = newSession(settings);
  status(`Settling ${settings.settle} s before the cold proof...`);
  await sleep(settings.settle);
  status("Cold proof running...");
  await oneProof("cold", settings);
  await postResults();
  state.running = false;
  setButtons(false);
  const i = campaignRun || 1;
  if (params.get("mode") === "cold" && i < settings.runs) {
    for (let left = settings.idle; left > 0; left--) {
      status(`Cold campaign: run ${i} of ${settings.runs} done. Reloading in ${left} s (keep the screen on).`);
      await sleep(1);
    }
    const next = new URLSearchParams(location.search);
    next.set("i", String(i + 1));
    next.set("campaign", campaignId);
    location.replace(`${location.pathname}?${next.toString()}`);
    return;
  }
  status(params.get("mode") === "cold" ? `Cold campaign finished (${settings.runs} runs).` : "Cold proof done. Reload the page for the next cold proof.");
}

async function runWarm() {
  const settings = readSettings();
  state.running = true;
  setButtons(true);
  if (!state.session) state.session = newSession(settings);
  const total = settings.warmup + settings.n;
  if (state.proofs === 0) {
    status(`Settling ${settings.settle} s, then the first (cold) proof...`);
    await sleep(settings.settle);
    await oneProof("cold", settings);
  }
  for (let k = 0; k < total; k++) {
    if (settings.gap > 0) await sleep(settings.gap);
    status(`Warm series: proof ${k + 1} of ${total}...`);
    await oneProof(k < settings.warmup ? "warmup" : "warm", settings);
  }
  await postResults();
  state.running = false;
  setButtons(false);
  status("Warm series done.");
}

async function main() {
  applyParams();
  setButtons(true);
  $("btnCold").onclick = () => runCold();
  $("btnWarm").onclick = () => runWarm();
  $("btnPost").onclick = () => postResults();
  if (typeof snarkjs === "undefined") {
    status("snarkjs.min.js did not load");
    return;
  }
  await holdWakeLock();
  try {
    state.art = await loadArtifacts();
  } catch (e) {
    status(`Download failed: ${e}`);
    return;
  }
  const d = state.art.download;
  log(`downloaded zkey ${d.zkeyBytes} B in ${d.zkeyMs.toFixed(0)} ms, wasm ${d.wasmBytes} B in ${d.wasmMs.toFixed(0)} ms (sizes match: ${d.sizesMatchManifest})`);
  log(`crossOriginIsolated ${window.crossOriginIsolated === true}, secure context ${window.isSecureContext === true}, wake lock: ${wakeLockState}`);
  setButtons(false);
  status("Ready.");
  const mode = params.get("mode");
  if (mode === "cold") await runCold();
  else if (mode === "warm") await runWarm();
}

main();
