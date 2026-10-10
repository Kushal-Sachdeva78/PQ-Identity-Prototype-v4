import Foundation
import UIKit

/// Launch bookkeeping, set once in PQIDPhoneApp.init (a cold proof is the first proof after it).
enum LaunchInfo {
    static var uptimeNs: UInt64 = 0
    static var utc = Date()
    static var sessionId = UUID().uuidString.lowercased()

    static func mark() {
        uptimeNs = DispatchTime.now().uptimeNanoseconds
        utc = Date()
        sessionId = UUID().uuidString.lowercased()
    }

    static var isUnderXCTest: Bool {
        ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
    }
}

enum Clock {
    static func nowNs() -> UInt64 { DispatchTime.now().uptimeNanoseconds }
    static func ms(_ from: UInt64, _ to: UInt64) -> Double { Double(to &- from) / 1_000_000 }

    private static let iso: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        f.timeZone = TimeZone(identifier: "UTC")
        return f
    }()

    static func utc(_ d: Date = Date()) -> String { iso.string(from: d) }

    static func compactUtc(_ d: Date = Date()) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        return f.string(from: d)
    }
}

/// Conditions recorded before and after every proof (docs/v4/PHONE_PROTOCOL.md, "Controls").
/// No device name, user name or identifier is recorded.
public struct DeviceSnapshot: Codable, Sendable {
    public var utc: String
    public var uptimeNs: UInt64
    public var thermalState: String
    public var batteryState: String
    public var batteryLevel: Float?
    public var lowPowerMode: Bool
    public var screenBrightness: Double?

    /// Must run on the main thread (UIKit).
    @MainActor static func capture() -> DeviceSnapshot {
        let dev = UIDevice.current
        dev.isBatteryMonitoringEnabled = true
        let level = dev.batteryLevel
        let battery: String
        switch dev.batteryState {
        case .unplugged: battery = "unplugged"
        case .charging: battery = "charging"
        case .full: battery = "full"
        default: battery = "unknown"
        }
        return DeviceSnapshot(
            utc: Clock.utc(),
            uptimeNs: Clock.nowNs(),
            thermalState: thermalName(ProcessInfo.processInfo.thermalState),
            batteryState: battery,
            batteryLevel: level < 0 ? nil : level,
            lowPowerMode: ProcessInfo.processInfo.isLowPowerModeEnabled,
            screenBrightness: currentBrightness()
        )
    }

    /// Takes the snapshot on the main thread from any thread.
    static func captureFromAnyThread() -> DeviceSnapshot {
        if Thread.isMainThread { return MainActor.assumeIsolated { capture() } }
        return DispatchQueue.main.sync { MainActor.assumeIsolated { capture() } }
    }

    @MainActor private static func currentBrightness() -> Double? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        guard let screen = scenes.first?.screen else { return nil }
        return Double(screen.brightness)
    }

    static func thermalName(_ s: ProcessInfo.ThermalState) -> String {
        switch s {
        case .nominal: return "nominal"
        case .fair: return "fair"
        case .serious: return "serious"
        case .critical: return "critical"
        @unknown default: return "unknown"
        }
    }
}

/// Static facts about the device and build (no personal data).
public struct DeviceInfo: Codable, Sendable {
    public var model: String
    public var systemName: String
    public var systemVersion: String
    public var isSimulator: Bool
    public var processorCount: Int
    public var activeProcessorCount: Int
    public var physicalMemoryBytes: UInt64

    @MainActor static func current() -> DeviceInfo {
        #if targetEnvironment(simulator)
        let sim = true
        #else
        let sim = false
        #endif
        let p = ProcessInfo.processInfo
        return DeviceInfo(
            model: modelIdentifier(),
            systemName: UIDevice.current.systemName,
            systemVersion: UIDevice.current.systemVersion,
            isSimulator: sim,
            processorCount: p.processorCount,
            activeProcessorCount: p.activeProcessorCount,
            physicalMemoryBytes: p.physicalMemory
        )
    }

    /// Hardware model identifier such as "iPhone15,4" (the simulator reports the simulated one).
    static func modelIdentifier() -> String {
        if let sim = ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] { return sim }
        var u = utsname()
        uname(&u)
        return withUnsafeBytes(of: &u.machine) { raw in
            String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
        }
    }
}
