import FactorSealKit
import SwiftUI

@main
struct FactorSealApp: App {
    var body: some Scene {
        WindowGroup {
            Root().ignoresSafeArea()
        }
    }
}

private struct Root: UIViewControllerRepresentable {
    func makeUIViewController(context: Context) -> UIViewController {
        MainViewControllerKt.mainViewController(core: RustCore())
    }

    func updateUIViewController(_ controller: UIViewController, context: Context) {}
}
