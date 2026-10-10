import SwiftUI
import UIKit

/// Runs the native proving series and shows the log (docs/v4/PHONE_PROTOCOL.md, native path).
@MainActor
final class BenchModel: ObservableObject {
    @Published var status = "Ready"
    @Published var lines: [String] = []
    @Published var running = false
    @Published var flash = false
    @Published var logFiles: [URL] = []

    private var bench: ProofBench?
    private let queue = DispatchQueue(label: "pqid.bench", qos: .userInitiated)

    func config(from s: Settings) -> ProofBench.Config {
        var c = ProofBench.Config()
        c.warmupCount = s.warmupCount
        c.warmCount = s.warmCount
        c.gapSec = s.gapSec
        c.preIdleSec = s.preIdleSec
        c.postIdleSec = s.postIdleSec
        c.flashMarkers = s.flashMarkers
        c.sampleFootprint = s.sampleFootprint
        c.coldSettleSec = s.coldSettleSec
        return c
    }

    /// The bench keeps the settings it was created with, for the whole launch (one log per launch).
    private func ensureBench(_ s: Settings) -> ProofBench? {
        if let b = bench { return b }
        do {
            let b = try ProofBench(config: config(from: s), context: "app")
            b.flashHook = { [weak self] on in self?.flash = on }
            bench = b
            return b
        } catch {
            status = "Setup failed: \(error)"
            return nil
        }
    }

    func run(coldOnly: Bool, settings: Settings) {
        guard !running, let b = ensureBench(settings) else { return }
        running = true
        UIApplication.shared.isIdleTimerDisabled = true
        status = coldOnly ? "Cold proof running..." : "Series running..."
        queue.async { [weak self] in
            let records = b.runSeries(coldOnly: coldOnly)
            Task { @MainActor in
                guard let self else { return }
                for r in records { self.lines.append(Self.describe(r)) }
                self.running = false
                UIApplication.shared.isIdleTimerDisabled = false
                self.status = records.isEmpty
                    ? "No cold proof: a proof already ran in this launch. Relaunch the app."
                    : "Done: \(records.count) proof(s). Log: \(b.logFileURL.lastPathComponent)"
                self.refreshFiles()
            }
        }
    }

    func checkHash(settings: Settings) {
        guard !running, let b = ensureBench(settings) else { return }
        running = true
        queue.async { [weak self] in
            b.checkZkeyHash()
            let match = b.log.artifacts.zkeySha256Match
            Task { @MainActor in
                self?.running = false
                self?.status = "zkey SHA-256 matches the pin: \(match.map { String($0) } ?? "not checked")"
                self?.refreshFiles()
            }
        }
    }

    func refreshFiles() {
        let dir = ProofBench.logDirectory()
        let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        logFiles = files.filter { $0.pathExtension == "json" }.sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    static func describe(_ r: ProofRecord) -> String {
        let prove = r.proveMs.map { String(format: "%.0f ms", $0) } ?? "failed"
        let mem = r.footprint.sampledPeakBytes.map { String(format: "%.0f MB", Double($0) / 1_048_576) } ?? "-"
        let ok = r.verified == true && r.publicSignalsMatch ? "verified" : "NOT verified"
        return "#\(r.index) \(r.kind.rawValue): prove \(prove), peak \(mem), \(ok), thermal \(r.before.thermalState)"
    }
}

/// Settings persisted across launches (a cold series is 30 launches with the same settings).
struct Settings: DynamicProperty {
    @AppStorage("autoColdOnLaunch") var autoColdOnLaunch = false
    @AppStorage("coldSettleSec") var coldSettleSec = 30.0
    @AppStorage("warmupCount") var warmupCount = 5
    @AppStorage("warmCount") var warmCount = 30
    @AppStorage("gapSec") var gapSec = 10.0
    @AppStorage("preIdleSec") var preIdleSec = 0.0
    @AppStorage("postIdleSec") var postIdleSec = 0.0
    @AppStorage("flashMarkers") var flashMarkers = false
    @AppStorage("sampleFootprint") var sampleFootprint = true
}

struct ContentView: View {
    @StateObject private var model = BenchModel()
    @State private var didAutoRun = false
    private var settings = Settings()

    var body: some View {
        ZStack {
            NavigationStack {
                Form {
                    Section("PQ-Identity v4, native (Mopro, arkworks), dev key") {
                        Text(model.status).font(.callout)
                        Button("Cold proof (first proof after launch)") { model.run(coldOnly: true, settings: settings) }
                            .disabled(model.running)
                        Button("Warm series (\(settings.warmupCount) warm-up + \(settings.warmCount) warm)") {
                            model.run(coldOnly: false, settings: settings)
                        }
                        .disabled(model.running)
                        Button("Check zkey SHA-256 (after the timed runs)") { model.checkHash(settings: settings) }
                            .disabled(model.running)
                    }
                    Section("Settings (kept across launches; recorded in every log)") {
                        Toggle("Run the cold proof automatically on launch", isOn: settings.$autoColdOnLaunch)
                        Stepper("Settle before cold proof: \(Int(settings.coldSettleSec)) s", value: settings.$coldSettleSec, in: 0...600, step: 10)
                        Stepper("Warm-up proofs: \(settings.warmupCount)", value: settings.$warmupCount, in: 0...20)
                        Stepper("Warm proofs: \(settings.warmCount)", value: settings.$warmCount, in: 1...100)
                        Stepper("Gap between proofs: \(Int(settings.gapSec)) s", value: settings.$gapSec, in: 0...120, step: 5)
                        Stepper("Idle before proof (energy): \(Int(settings.preIdleSec)) s", value: settings.$preIdleSec, in: 0...60, step: 1)
                        Stepper("Idle after proof (energy): \(Int(settings.postIdleSec)) s", value: settings.$postIdleSec, in: 0...60, step: 1)
                        Toggle("Screen flash markers at proof start/end (energy)", isOn: settings.$flashMarkers)
                        Toggle("Sample memory every 5 ms during the proof", isOn: settings.$sampleFootprint)
                    }
                    Section("This launch") {
                        ForEach(model.lines, id: \.self) { Text($0).font(.caption.monospaced()) }
                    }
                    Section("Logs (Files app: On My iPhone > PQIDPhone > pqid_phone)") {
                        ForEach(model.logFiles, id: \.self) { url in
                            ShareLink(item: url) { Text(url.lastPathComponent).font(.caption.monospaced()) }
                        }
                    }
                }
                .navigationTitle("PQID v4 prover")
            }
            if model.flash {
                Color.white.ignoresSafeArea()
            }
        }
        .onAppear {
            model.refreshFiles()
            if settings.autoColdOnLaunch && !didAutoRun && !LaunchInfo.isUnderXCTest && ProofBench.nextIsCold {
                didAutoRun = true
                model.run(coldOnly: true, settings: settings)
            }
        }
    }
}
