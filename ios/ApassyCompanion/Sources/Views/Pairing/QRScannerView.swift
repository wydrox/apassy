import SwiftUI
import UIKit
import VisionKit

/// The camera view that reads QR codes, and nothing else: no other barcode type.
struct QRScannerView: UIViewControllerRepresentable {
    /// Called with the text of each QR code that the camera finds.
    let onCode: @MainActor (String) -> Void
    /// Called when the scanner cannot start.
    let onFailure: @MainActor () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onCode: onCode)
    }

    func makeUIViewController(context: Context) -> ScannerHostController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            recognizesMultipleItems: false,
            isHighFrameRateTrackingEnabled: false,
            isPinchToZoomEnabled: true,
            isGuidanceEnabled: true,
            isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        let host = ScannerHostController(scanner: scanner)
        host.onFailure = onFailure
        return host
    }

    func updateUIViewController(_ host: ScannerHostController, context: Context) {
        context.coordinator.onCode = onCode
        host.onFailure = onFailure
    }

    static func dismantleUIViewController(_ host: ScannerHostController, coordinator: Coordinator) {
        host.scanner.stopScanning()
    }

    /// Holds the scanner and starts it when the view is on the screen. The camera cannot start
    /// before that, and `DataScannerViewController` cannot be subclassed.
    final class ScannerHostController: UIViewController {
        let scanner: DataScannerViewController
        var onFailure: @MainActor () -> Void = {}

        init(scanner: DataScannerViewController) {
            self.scanner = scanner
            super.init(nibName: nil, bundle: nil)
        }

        @available(*, unavailable)
        required init?(coder: NSCoder) {
            fatalError("init(coder:) is not used")
        }

        override func viewDidLoad() {
            super.viewDidLoad()
            addChild(scanner)
            scanner.view.frame = view.bounds
            scanner.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
            view.addSubview(scanner.view)
            scanner.didMove(toParent: self)
        }

        override func viewDidAppear(_ animated: Bool) {
            super.viewDidAppear(animated)
            guard !scanner.isScanning else { return }
            do {
                try scanner.startScanning()
            } catch {
                onFailure()
            }
        }
    }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        var onCode: @MainActor (String) -> Void

        init(onCode: @escaping @MainActor (String) -> Void) {
            self.onCode = onCode
        }

        func dataScanner(
            _ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem],
            allItems: [RecognizedItem]
        ) {
            deliver(addedItems)
        }

        func dataScanner(_ dataScanner: DataScannerViewController, didTapOn item: RecognizedItem) {
            deliver([item])
        }

        private func deliver(_ items: [RecognizedItem]) {
            for item in items {
                if case .barcode(let barcode) = item, let payload = barcode.payloadStringValue {
                    onCode(payload)
                    return
                }
            }
        }
    }
}
