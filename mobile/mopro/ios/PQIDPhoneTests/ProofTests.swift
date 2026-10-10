import XCTest
@testable import PQIDPhone

/// One v4 proof (plus verification) inside the host app, used by .github/workflows/ios-mopro.yml
/// on a simulator. The log line "PQID_PHONE_LOG_JSON {...}" is extracted from the xcodebuild
/// output by the workflow. A simulator run checks that the native path works; it is NOT a phone
/// measurement (the log's label says so).
///
/// Environment (set as TEST_RUNNER_PQID_WARM_RUNS in xcodebuild's environment [VERIFY that the
/// prefix reaches a hosted unit test]):
///   PQID_WARM_RUNS  number of warm proofs after the cold one (default 0)
final class ProofTests: XCTestCase {
    func testColdProofVerifiesOnSimulator() throws {
        let env = ProcessInfo.processInfo.environment
        var cfg = ProofBench.Config()
        cfg.warmupCount = 0
        cfg.warmCount = Int(env["PQID_WARM_RUNS"] ?? "") ?? 0
        cfg.gapSec = 0
        cfg.requireNominalThermal = false
        cfg.sampleFootprint = true

        let bench = try ProofBench(bundle: Bundle.main, config: cfg, context: "xctest")
        XCTAssertTrue(bench.log.artifacts.moproInputSha256Match, "bundled input differs from its meta file")
        XCTAssertTrue(ProofBench.nextIsCold, "a proof already ran in this test process")

        let records = bench.runSeries(coldOnly: cfg.warmCount == 0)
        bench.checkZkeyHash()
        print("PQID_PHONE_LOG_JSON " + (try bench.logJSON(compact: true)))

        XCTAssertEqual(records.first?.kind, .cold)
        XCTAssertEqual(records.count, 1 + cfg.warmCount)
        XCTAssertEqual(bench.log.artifacts.zkeySha256Match, true, "bundled zkey is not the pinned dev key")
        for r in records {
            XCTAssertNil(r.error, r.error ?? "")
            XCTAssertEqual(r.verified, true, "proof \(r.index) did not verify")
            XCTAssertTrue(r.publicSignalsMatch, "proof \(r.index): public signals differ from v4_input.meta.json")
            XCTAssertNotNil(r.proveMs)
        }
    }
}
