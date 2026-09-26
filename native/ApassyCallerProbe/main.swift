// Caller probe for the smoke checks in scripts/build-app.sh.
//
// The probe starts one program as its child and waits for it. The child
// gets the stdin, stdout, and stderr of the probe. So the probe is the
// parent process of the child.
//
// scripts/build-app.sh signs the probe as the main executable of scratch
// copies of Apassy.app, then starts the helpers through it. This shows that
// the helper caller check accepts the signed Apassy app that contains the
// helper and refuses other parents. The probe never goes into Apassy.app.
//
// Usage: probe <program>

import Foundation

let arguments = CommandLine.arguments
guard arguments.count == 2 else {
    FileHandle.standardError.write(Data("usage: probe <program>\n".utf8))
    exit(2)
}
let child = Process()
child.executableURL = URL(fileURLWithPath: arguments[1])
do {
    try child.run()
} catch {
    FileHandle.standardError.write(Data("probe: cannot start \(arguments[1]): \(error)\n".utf8))
    exit(3)
}
child.waitUntilExit()
exit(child.terminationStatus)
