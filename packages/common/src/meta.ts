import os from "node:os";
import { execFileSync } from "node:child_process";

export interface HostMeta {
  cpuModel: string;
  logicalCores: number;
  totalMemGiB: number;
  platform: string;
  osRelease: string;
  osBuild: string;
  nodeVersion: string;
  timestampUtc: string;
}

/**
 * Host metadata embedded into every results/*.json file, per the integrity
 * rules (CPU model, OS build, toolchain versions are mandatory provenance).
 */
export function hostMeta(): HostMeta {
  let osBuild = os.release();
  if (process.platform === "win32") {
    try {
      const ver = execFileSync("cmd", ["/c", "ver"], { encoding: "utf8" }).trim();
      const m = /\[Version ([\d.]+)\]/.exec(ver);
      if (m && m[1]) osBuild = m[1];
    } catch {
      /* fall back to os.release() */
    }
  }
  const cpus = os.cpus();
  return {
    cpuModel: cpus[0]?.model ?? "unknown",
    logicalCores: cpus.length,
    totalMemGiB: Math.round((os.totalmem() / 1024 ** 3) * 10) / 10,
    platform: `${process.platform} ${os.arch()}`,
    osRelease: os.release(),
    osBuild,
    nodeVersion: process.version,
    timestampUtc: new Date().toISOString(),
  };
}

export interface WslMeta {
  kernel: string;
  distro: string;
  gcc: string;
  cmake: string;
  python: string;
}

/** Toolchain metadata from inside WSL (used for rapidsnark / liboqs results). */
export function wslMeta(): WslMeta {
  const run = (cmd: string): string => {
    try {
      const raw = execFileSync("wsl", ["-u", "root", "-e", "bash", "-lc", cmd], {
        encoding: "utf8",
      });
      // wsl.exe can interleave NUL bytes and CR; strip them without a
      // control-char regex by splitting on the NUL/CR code points.
      return raw
        .split(String.fromCharCode(0))
        .join("")
        .split(String.fromCharCode(13))
        .join("")
        .trim();
    } catch {
      return "unavailable";
    }
  };
  return {
    kernel: run("uname -r"),
    distro: run("grep PRETTY_NAME /etc/os-release | cut -d'\"' -f2"),
    gcc: run("gcc --version | head -1"),
    cmake: run("cmake --version | head -1"),
    python: run("/root/pqid-native/venv/bin/python --version 2>/dev/null || python3 --version"),
  };
}
