import SwiftUI

@main
struct MirageGUIApp: App {
    var body: some Scene {
        WindowGroup("Mirage") {
            ContentView()
                .frame(minWidth: 540, minHeight: 520)
        }
        .windowResizability(.contentSize)
    }
}
