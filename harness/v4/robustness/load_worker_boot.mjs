// Worker-thread entry of the load test (harness/v4/robustness/load.ts). Two run-time fixes for
// running the verifier inside a worker thread; node_modules and packages/ are unchanged.
//
// 1. Node does not apply the parent's tsx loader (--import tsx) to worker threads: a .ts worker
//    entry would be type-stripped natively, which fails on TypeScript parameter properties in
//    packages/v4. So this bootstrap registers tsx inside the worker.
// 2. snarkjs builds its bn128 curve with a thread pool through ffjavascript, which spawns its
//    threads with the web-worker package. web-worker decides when it is first loaded whether it
//    is one of its own pool threads by reading worker_threads.isMainThread: inside any worker
//    thread it takes the pool-thread branch, so ffjavascript gets no Worker class and every
//    snarkjs.groth16.verify throws (the verifier then rejects every proof). The bootstrap loads
//    web-worker once with isMainThread reading true, so the module is cached in its main-thread
//    form (a Worker class that starts real nested threads), then restores the flag. Each load
//    worker therefore has its own bn128 thread pool, as a separate verifier process would.
import { workerData } from "node:worker_threads";
import threads from "node:worker_threads";
import { createRequire } from "node:module";
import { register } from "tsx/esm/api";

const require = createRequire(import.meta.url);
const desc = Object.getOwnPropertyDescriptor(threads, "isMainThread");
Object.defineProperty(threads, "isMainThread", { value: true, configurable: true, writable: true, enumerable: true });
try {
  require("web-worker");
} finally {
  if (desc) Object.defineProperty(threads, "isMainThread", desc);
}

register();
await import(workerData.__entry);
