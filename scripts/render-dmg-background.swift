// Regenerate the Finder background with: swift scripts/render-dmg-background.swift
// Uses macOS AppKit only. Coordinates match scripts/layout-dmg.sh.
import AppKit

let output = URL(fileURLWithPath: CommandLine.arguments.dropFirst().first ?? "packaging", isDirectory: true)
let width = 720, height = 480
func color(_ hex: UInt32, _ alpha: CGFloat = 1) -> NSColor {
    NSColor(srgbRed: CGFloat((hex >> 16) & 255) / 255,
            green: CGFloat((hex >> 8) & 255) / 255,
            blue: CGFloat(hex & 255) / 255, alpha: alpha)
}
let ink = color(0x0e1820), muted = color(0x62666d), blue = color(0x0a77fe)
func render(scale: Int) -> NSBitmapImageRep {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: width * scale,
        pixelsHigh: height * scale, bitsPerSample: 8, samplesPerPixel: 4,
        hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
        bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    let bitmapContext = NSGraphicsContext(bitmapImageRep: rep)!
    NSGraphicsContext.current = NSGraphicsContext(cgContext: bitmapContext.cgContext, flipped: true)
    let transform = NSAffineTransform()
    transform.translateX(by: 0, yBy: CGFloat(height * scale))
    transform.scaleX(by: CGFloat(scale), yBy: -CGFloat(scale))
    transform.concat()
    func rect(_ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat, _ fill: NSColor, radius: CGFloat = 0) {
        fill.setFill()
        NSBezierPath(roundedRect: NSRect(x: x, y: y, width: w, height: h), xRadius: radius, yRadius: radius).fill()
    }
    func text(_ string: String, x: CGFloat, y: CGFloat, size: CGFloat, tint: NSColor = ink, weight: NSFont.Weight = .regular, centered: Bool = false) {
        let style = NSMutableParagraphStyle()
        style.alignment = centered ? .center : .left
        let attrs: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: size, weight: weight), .foregroundColor: tint, .paragraphStyle: style]
        NSAttributedString(string: string, attributes: attrs).draw(with: NSRect(x: x, y: y, width: centered ? 720 : 650 - x, height: size * 1.5), options: [.usesLineFragmentOrigin], context: nil)
    }
    rect(0, 0, 720, 480, color(0xfbfbfd))
    // The same quiet grid and palette as site/src/layouts/Page.astro.
    for x in stride(from: 0, through: 720, by: 40) { rect(CGFloat(x), 0, 0.5, 480, color(0x0e1820, 0.04)) }
    for y in stride(from: 0, through: 480, by: 40) { rect(0, CGFloat(y), 720, 0.5, color(0x0e1820, 0.04)) }
    text("Install Apassy.", x: 0, y: 82, size: 48, weight: .medium, centered: true)
    text("Drag Apassy to Applications.", x: 0, y: 146, size: 18, tint: muted, centered: true)
    rect(42, 194, 636, 162, color(0xffffff), radius: 22)
    let outline = NSBezierPath(roundedRect: NSRect(x: 42, y: 194, width: 636, height: 162), xRadius: 22, yRadius: 22)
    color(0x0e1820, 0.09).setStroke(); outline.lineWidth = 1; outline.stroke()
    // Native Finder icons occupy (190,260) and (530,260). Do not paint replicas.
    rect(324, 234, 72, 48, color(0x0a77fe, 0.07), radius: 24)
    let arrow = NSBezierPath()
    arrow.move(to: NSPoint(x: 343, y: 258)); arrow.line(to: NSPoint(x: 377, y: 258))
    arrow.move(to: NSPoint(x: 369, y: 250)); arrow.line(to: NSPoint(x: 377, y: 258)); arrow.line(to: NSPoint(x: 369, y: 266))
    arrow.lineWidth = 2; arrow.lineCapStyle = .round; arrow.lineJoinStyle = .round
    blue.setStroke(); arrow.stroke()
    NSGraphicsContext.restoreGraphicsState()
    // Set the logical size after drawing; AppKit otherwise scales the context
    // a second time for the Retina representation.
    rep.size = NSSize(width: width, height: height)
    return rep
}
try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
let standard = render(scale: 1), retina = render(scale: 2)
try standard.representation(using: .png, properties: [:])!.write(to: output.appendingPathComponent("dmg-background.png"))
try NSBitmapImageRep.representationOfImageReps(in: [standard, retina], using: .tiff, properties: [.compressionMethod: NSBitmapImageRep.TIFFCompression.lzw.rawValue])!.write(to: output.appendingPathComponent("dmg-background.tiff"))
print("Wrote 720 × 480 background (1× PNG and 1×/2× TIFF).")
