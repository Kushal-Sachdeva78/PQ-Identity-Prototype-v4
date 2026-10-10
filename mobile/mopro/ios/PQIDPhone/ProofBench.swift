import CryptoKit
import Foundation

// Native (Mopro) proving runs for PQ-Identity v4 (docs/v4/PHONE_PROTOCOL.md).
//
// Definitions used in every log:
//   cold   = the first proof after the app process starts (the user relaunches the app for
//            each cold run; the app never counts a later proof as cold);
//   warmup = proofs after the first one that are not analysed (config.warmupCount);
//   warm   = later proofs in the same process.
//   proveMs  = wall time of generateCircomProof (Mopro: witness generation with rust-witness
//              plus the arkworks Groth16 proof, including whatever zkey reading Mopro does
//              inside the call) [VERIFY whether Mopro caches the parsed zkey between calls].
//   verifyMs = wall time of verifyCircomProof, run after the post-idle window (not part of
//              the energy window).
// Values that depend on the device (all timings, memory, thermal) are [M] only for the
// device named in device.model; simulator logs are labelled as not a phone measurement.

public enum ProofKind: String, Codable {
    case cold, warmup, warm
}

public struct MarkerEvent: Codable {
    public var event: String
    public var utc: String
    public var uptimeNs: UInt64
}

public struct FootprintStats: Codable {
    public var samplerOn: Bool
    public var sampleIntervalMs: Int
    public var samples: Int
    public var baselineBytes: UInt64?
    public var sampledPeakBytes: UInt64?
    public var sampledPeakAboveBaselineBytes: Int64?
    public var lifetimePeakAfterBytes: Int64?
}

public struct ProofRecord: Codable {
    public var index: Int
    public var kind: ProofKind
    public var sinceLaunchMs: Double
    public var startUtc: String
    public var proveMs: Double?
    public var verifyMs: Double?
    public var verified: Bool?
    public var publicSignalsMatch: Bool
    public var footprint: FootprintStats
    public var thermalWaitSec: Double
    public var thermalNotNominalAtStart: Bool
    public var before: DeviceSnapshot
    public var after: DeviceSnapshot?
    public var markers: [MarkerEvent]
    public var error: String?
}

public struct InputMeta: Codable {
    public struct Artifact: Codable { public var path: String; public var sha256: String; public var bytes: Int }
    public struct Artifacts: Codable { public var wasm: Artifact; public var zkey: Artifact; public var vkey: Artifact }
    public var keyLabel: String
    public var inputSha256: String
    public var moproInputSha256: String
    public var publicSignals: [String]
    public var publicSignalsSha256: String
    public var artifacts: Artifacts
}

public struct SessionLog: Codable {
    public struct App: Codable {
        public var bundleVersion: String
        public var moproCliVersion: String
        public var glueInfo: String
        public var swiftBuildConfiguration: String
    }
    public struct Artifacts: Codable {
        public var zkeyFile: String
        public var zkeyBytes: Int64?
        public var zkeyExpectedSha256: String
        public var zkeySha256Checked: Bool
        public var zkeySha256Match: Bool?
        public var moproInputSha256Match: Bool
        public var inputSha256: String
        public var expectedPublicSignalsSha256: String
        public var circuit: String
        public var proofLib: String
        public var witnessGenerator: String
    }
    public struct ProtocolInfo: Codable {
        public var cold: String
        public var warm: String
        public var warmupCount: Int
        public var warmCount: Int
        public var gapSec: Double
        public var preIdleSec: Double
        public var postIdleSec: Double
        public var flashMarkers: Bool
        public var requireNominalThermal: Bool
        public var coldSettleSec: Double
    }

    public var schema = "pqid/v4-phone-native/v1"
    public var path = "native-mopro"
    public var label: String
    public var keyLabel: String
    public var context: String
    public var sessionId: String
    public var launchUtc: String
    public var app: App
    public var device: DeviceInfo
    public var artifacts: Artifacts
    public var protocolInfo: ProtocolInfo
    public var records: [ProofRecord]
    public var notes: [String]
}

public enum ProofBenchError: Error, CustomStringConvertible {
    case missingResource(String)
    case badInput(String)

    public var description: String {
        switch self {
        case .missingResource(let s): return "missing bundle resource \(s)"
        case .badInput(let s): return "bad input: \(s)"
        }
    }
}

public final class ProofBench {
    public struct Config {
        public var warmupCount = 5
        public var warmCount = 30
        public var gapSec: Double = 10
        public var preIdleSec: Double = 0
        public var postIdleSec: Double = 0
        public var flashMarkers = false
        public var flashMs = 300
        public var sampleFootprint = true
        public var sampleIntervalMs = 5
        public var requireNominalThermal = true
        public var maxThermalWaitSec: Double = 600
        public var coldSettleSec: Double = 0
        public init() {}
    }

    public let zkeyPath: String
    public let config: Config
    /// Called with true/false to show/hide the full-screen marker flash (always on the main queue).
    public var flashHook: ((Bool) -> Void)?
    public private(set) var log: SessionLog

    private let inputJSON: String
    private let meta: InputMeta
    private var proofsThisProcess = 0

    /// Shared across instances: "cold" is per process, not per ProofBench object.
    private static var processProofCount = 0
    private static let countLock = NSLock()

    public init(bundle: Bundle = .main, config: Config = Config(), context: String) throws {
        guard let zkey = bundle.path(forResource: "credential_auth_v4_dev", ofType: "zkey") else {
            throw ProofBenchError.missingResource("credential_auth_v4_dev.zkey")
        }
        guard let inputURL = bundle.url(forResource: "v4_input.mopro", withExtension: "json") else {
            throw ProofBenchError.missingResource("v4_input.mopro.json")
        }
        guard let metaURL = bundle.url(forResource: "v4_input.meta", withExtension: "json") else {
            throw ProofBenchError.missingResource("v4_input.meta.json")
        }
        let raw = try String(contentsOf: inputURL, encoding: .utf8)
        let trimmed = raw.trimmingCharacters(in: .newlines)
        let meta = try JSONDecoder().decode(InputMeta.self, from: Data(contentsOf: metaURL))
        let inputHash = ProofBench.sha256Hex(Data(trimmed.utf8))

        // file size from metadata only: reading the zkey here would warm the page cache before the cold proof
        let attrs = try? FileManager.default.attributesOfItem(atPath: zkey)
        let zkeyBytes = (attrs?[.size] as? NSNumber)?.int64Value

        let info = Bundle.main.infoDictionary ?? [:]
        #if DEBUG
        let swiftConfig = "Debug"
        #else
        let swiftConfig = "Release"
        #endif
        let device = ProofBench.onMain { DeviceInfo.current() }
        let label = device.isSimulator
            ? "[M-sim] iOS simulator on the build host: NOT a phone measurement (dev key)"
            : "[M] native Mopro proving on the device in device.model (dev key); device values [VERIFY] against the device used"
        let initialLog = SessionLog(
            label: label,
            keyLabel: meta.keyLabel,
            context: context,
            sessionId: LaunchInfo.sessionId,
            launchUtc: Clock.utc(LaunchInfo.utc),
            app: .init(
                bundleVersion: "\(info["CFBundleShortVersionString"] ?? "?") (\(info["CFBundleVersion"] ?? "?"))",
                moproCliVersion: (info["PQIDMoproCliVersion"] as? String) ?? "unknown",
                glueInfo: pqidV4GlueInfo(),
                swiftBuildConfiguration: swiftConfig
            ),
            device: device,
            artifacts: .init(
                zkeyFile: "credential_auth_v4_dev.zkey",
                zkeyBytes: zkeyBytes,
                zkeyExpectedSha256: meta.artifacts.zkey.sha256,
                zkeySha256Checked: false,
                zkeySha256Match: nil,
                moproInputSha256Match: inputHash == meta.moproInputSha256,
                inputSha256: meta.inputSha256,
                expectedPublicSignalsSha256: meta.publicSignalsSha256,
                circuit: "credential_auth_v4 (details: circuits/build/v4/circuit_info.json)",
                proofLib: "arkworks",
                witnessGenerator: "rust-witness"
            ),
            protocolInfo: .init(
                cold: "first proof after the app process starts",
                warm: "later proofs in the same process, after warmupCount unanalysed proofs",
                warmupCount: config.warmupCount,
                warmCount: config.warmCount,
                gapSec: config.gapSec,
                preIdleSec: config.preIdleSec,
                postIdleSec: config.postIdleSec,
                flashMarkers: config.flashMarkers,
                requireNominalThermal: config.requireNominalThermal,
                coldSettleSec: config.coldSettleSec
            ),
            records: [],
            notes: []
        )
        self.zkeyPath = zkey
        self.config = config
        self.inputJSON = trimmed
        self.meta = meta
        self.log = initialLog
        if inputHash != meta.moproInputSha256 {
            throw ProofBenchError.badInput("v4_input.mopro.json does not match v4_input.meta.json")
        }
    }

    /// True when no proof has run in this process yet (the next proof is cold).
    public static var nextIsCold: Bool {
        countLock.lock(); defer { countLock.unlock() }
        return processProofCount == 0
    }

    // MARK: - series

    /// One cold proof (only if none ran in this process), then warmup and warm proofs as configured.
    /// Blocking: call from a background queue in the app. Returns the new records.
    @discardableResult
    public func runSeries(coldOnly: Bool) -> [ProofRecord] {
        var out: [ProofRecord] = []
        if Self.nextIsCold {
            if config.coldSettleSec > 0 { Thread.sleep(forTimeInterval: config.coldSettleSec) }
            out.append(runProof(kind: .cold))
        } else if coldOnly {
            log.notes.append("\(Clock.utc()): cold run requested but a proof already ran in this process; relaunch the app")
            persist()
            return out
        }
        if coldOnly { return out }
        for i in 0..<(config.warmupCount + config.warmCount) {
            if config.gapSec > 0 { Thread.sleep(forTimeInterval: config.gapSec) }
            out.append(runProof(kind: i < config.warmupCount ? .warmup : .warm))
        }
        return out
    }

    // MARK: - one proof

    private func runProof(kind: ProofKind) -> ProofRecord {
        Self.countLock.lock()
        Self.processProofCount += 1
        let index = Self.processProofCount
        Self.countLock.unlock()
        proofsThisProcess += 1

        // thermal gate (protocol: start only at nominal; otherwise wait, then run flagged)
        var waited = 0.0
        if config.requireNominalThermal {
            while ProcessInfo.processInfo.thermalState != .nominal && waited < config.maxThermalWaitSec {
                Thread.sleep(forTimeInterval: 5)
                waited += 5
            }
        }
        let notNominal = ProcessInfo.processInfo.thermalState != .nominal

        var markers: [MarkerEvent] = []
        func mark(_ e: String) { markers.append(MarkerEvent(event: e, utc: Clock.utc(), uptimeNs: Clock.nowNs())) }
        func flash() {
            guard config.flashMarkers, let hook = flashHook else { return }
            DispatchQueue.main.async { hook(true) }
            mark("flash_on")
            Thread.sleep(forTimeInterval: Double(config.flashMs) / 1000)
            DispatchQueue.main.async { hook(false) }
            mark("flash_off")
        }

        let before = DeviceSnapshot.captureFromAnyThread()
        if config.preIdleSec > 0 {
            mark("pre_idle_start")
            Thread.sleep(forTimeInterval: config.preIdleSec)
        }
        flash()

        let baseline = MemoryProbe.read()?.physFootprint
        let sampler = FootprintSampler(intervalMs: config.sampleIntervalMs)
        if config.sampleFootprint { sampler.start() }

        var record = ProofRecord(
            index: index, kind: kind,
            sinceLaunchMs: Clock.ms(LaunchInfo.uptimeNs, Clock.nowNs()),
            startUtc: Clock.utc(),
            proveMs: nil, verifyMs: nil, verified: nil, publicSignalsMatch: false,
            footprint: FootprintStats(samplerOn: config.sampleFootprint, sampleIntervalMs: config.sampleIntervalMs,
                                      samples: 0, baselineBytes: baseline, sampledPeakBytes: nil,
                                      sampledPeakAboveBaselineBytes: nil, lifetimePeakAfterBytes: nil),
            thermalWaitSec: waited, thermalNotNominalAtStart: notNominal,
            before: before, after: nil, markers: [], error: nil)

        var result: CircomProofResult?
        mark("proof_start")
        let t0 = Clock.nowNs()
        do {
            result = try generateCircomProof(zkeyPath: zkeyPath, circuitInputs: inputJSON, proofLib: ProofLib.arkworks)
        } catch {
            record.error = "generateCircomProof: \(error)"
        }
        let t1 = Clock.nowNs()
        mark("proof_end")
        if record.error == nil { record.proveMs = Clock.ms(t0, t1) }

        if config.sampleFootprint {
            let s = sampler.stop()
            record.footprint.samples = s.samples
            record.footprint.sampledPeakBytes = s.peak
            if let b = baseline { record.footprint.sampledPeakAboveBaselineBytes = Int64(s.peak) - Int64(b) }
        }
        record.footprint.lifetimePeakAfterBytes = MemoryProbe.read()?.lifetimePeak

        flash()
        if config.postIdleSec > 0 {
            Thread.sleep(forTimeInterval: config.postIdleSec)
            mark("post_idle_end")
        }

        if let r = result {
            // CircomProofResult.inputs: the public signals as decimal strings [VERIFY type in the generated mopro.swift]
            record.publicSignalsMatch = (r.inputs == meta.publicSignals)
            let v0 = Clock.nowNs()
            do {
                record.verified = try verifyCircomProof(zkeyPath: zkeyPath, proofResult: r, proofLib: ProofLib.arkworks)
                record.verifyMs = Clock.ms(v0, Clock.nowNs())
            } catch {
                record.verified = false
                record.error = "verifyCircomProof: \(error)"
            }
        }
        record.after = DeviceSnapshot.captureFromAnyThread()
        record.markers = markers
        log.records.append(record)
        persist()
        return record
    }

    // MARK: - after the series

    /// SHA-256 of the bundled zkey against the pinned value. Reads 11 MB, so it runs only after
    /// the timed proofs (never before a cold proof).
    public func checkZkeyHash() {
        guard let data = FileManager.default.contents(atPath: zkeyPath) else {
            log.notes.append("zkey could not be read for hashing")
            persist()
            return
        }
        log.artifacts.zkeySha256Checked = true
        log.artifacts.zkeySha256Match = (Self.sha256Hex(data) == meta.artifacts.zkey.sha256)
        persist()
    }

    public func logJSON(compact: Bool) throws -> String {
        let enc = JSONEncoder()
        enc.outputFormatting = compact ? [.sortedKeys] : [.sortedKeys, .prettyPrinted]
        return String(decoding: try enc.encode(log), as: UTF8.self)
    }

    /// Documents/pqid_phone/native_<launch utc>_<session>.json (one file per app launch).
    public static func logDirectory() -> URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return docs.appendingPathComponent("pqid_phone", isDirectory: true)
    }

    public var logFileURL: URL {
        let sid = String(log.sessionId.prefix(8))
        return Self.logDirectory().appendingPathComponent("native_\(Clock.compactUtc(LaunchInfo.utc))_\(sid).json")
    }

    public func persist() {
        do {
            try FileManager.default.createDirectory(at: Self.logDirectory(), withIntermediateDirectories: true)
            let json = try logJSON(compact: false)
            try Data(json.utf8).write(to: logFileURL, options: .atomic)
        } catch {
            print("PQID persist failed: \(error)")
        }
    }

    // MARK: - helpers

    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func onMain<T: Sendable>(_ body: @MainActor () -> T) -> T {
        if Thread.isMainThread { return MainActor.assumeIsolated { body() } }
        return DispatchQueue.main.sync { MainActor.assumeIsolated { body() } }
    }
}
