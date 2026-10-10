import Darwin
import Foundation

/// Process memory from the Mach task_info(TASK_VM_INFO) call.
///
/// - `phys_footprint` (task_vm_info rev1) is the physical footprint the system accounts to the
///   process (the number Xcode's memory gauge and jetsam use).
/// - `ledger_phys_footprint_peak` (rev3) is the process-lifetime peak of that footprint.
/// Field revisions: xnu osfmk/mach/task_info.h
/// (https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/osfmk/mach/task_info.h).
public enum MemoryProbe {
    public struct Reading {
        public let physFootprint: UInt64
        /// nil when the kernel returned fewer fields than rev3.
        public let lifetimePeak: Int64?
    }

    public static func read() -> Reading? {
        var info = task_vm_info_data_t()
        let wordSize = MemoryLayout<natural_t>.size
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / wordSize)
        let kr: kern_return_t = withUnsafeMutablePointer(to: &info) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), intPtr, &count)
            }
        }
        guard kr == KERN_SUCCESS else { return nil }
        let returnedBytes = Int(count) * wordSize
        var peak: Int64? = nil
        if let off = MemoryLayout<task_vm_info_data_t>.offset(of: \task_vm_info_data_t.ledger_phys_footprint_peak),
           returnedBytes >= off + MemoryLayout<Int64>.size {
            peak = info.ledger_phys_footprint_peak
        }
        return Reading(physFootprint: info.phys_footprint, lifetimePeak: peak)
    }
}

/// Samples phys_footprint on a timer while a proof runs and keeps the maximum.
/// Sampling can miss a spike shorter than the interval; the lifetime peak (rev3) cannot, but
/// it covers the whole process, so both are logged.
final class FootprintSampler {
    private let queue = DispatchQueue(label: "pqid.footprint.sampler", qos: .userInteractive)
    private var timer: DispatchSourceTimer?
    private let lock = NSLock()
    private var peak: UInt64 = 0
    private var samples = 0
    let intervalMs: Int

    init(intervalMs: Int) {
        self.intervalMs = max(1, intervalMs)
    }

    func start() {
        lock.lock(); peak = 0; samples = 0; lock.unlock()
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now(), repeating: .milliseconds(intervalMs), leeway: .milliseconds(1))
        t.setEventHandler { [weak self] in self?.sample() }
        timer = t
        t.resume()
    }

    /// Stops the timer, takes one last sample, returns (peak bytes, number of samples).
    func stop() -> (peak: UInt64, samples: Int) {
        timer?.cancel()
        timer = nil
        queue.sync {}  // drain a sample in flight
        sample()
        lock.lock(); defer { lock.unlock() }
        return (peak, samples)
    }

    private func sample() {
        guard let r = MemoryProbe.read() else { return }
        lock.lock()
        if r.physFootprint > peak { peak = r.physFootprint }
        samples += 1
        lock.unlock()
    }
}
