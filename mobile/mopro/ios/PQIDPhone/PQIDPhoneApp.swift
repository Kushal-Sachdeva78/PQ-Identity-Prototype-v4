import SwiftUI

@main
struct PQIDPhoneApp: App {
    init() {
        // A cold proof is the first proof after this point (docs/v4/PHONE_PROTOCOL.md).
        LaunchInfo.mark()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
