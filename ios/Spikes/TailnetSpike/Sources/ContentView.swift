import SwiftUI

struct ContentView: View {
    @ObservedObject var model: SpikeModel
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        NavigationStack {
            Form {
                NodeSection(model: model)
                JoinSection(model: model)
                TargetSection(model: model)
                MeasureSection(model: model)
                ResourcesSection(model: model)
                PrivacySection(model: model)
                MoreSection(model: model)
            }
            .navigationTitle("Tailnet spike")
        }
        .onChange(of: scenePhase, initial: true) { _, phase in
            model.scenePhaseChanged(phase)
        }
    }
}

private func ms(_ value: Double?) -> String {
    value.map { String(format: "%.0f ms", $0) } ?? "–"
}

private func megabytes(_ value: Double) -> String {
    String(format: "%.1f MB", value)
}

struct NodeSection: View {
    @ObservedObject var model: SpikeModel

    var body: some View {
        Section("Node") {
            LabeledContent("State", value: model.state)
            LabeledContent("Backend", value: model.backendState.isEmpty ? "–" : model.backendState)
            if !model.selfIPs.isEmpty {
                LabeledContent("This node", value: model.selfIPs)
            }
            if !model.tailnetName.isEmpty {
                LabeledContent("Tailnet", value: model.tailnetName)
            }
            LabeledContent("Path to the Mac", value: model.peerPath.isEmpty ? "–" : model.peerPath)
            if model.authURL != nil {
                Button("Sign in to Tailscale (in-app sheet)") { model.signIn(inApp: true) }
                Button("Sign in in Safari") { model.signIn(inApp: false) }
            }
            ForEach(model.authURLNotes, id: \.self) { note in
                Text("Sign-in URL via \(note)").font(.caption)
            }
            NavigationLink("Peers (\(model.peers.count))") {
                List(model.peers, id: \.self) { Text($0).font(.caption.monospaced()) }
                    .navigationTitle("Peers")
            }
        }
    }
}

struct JoinSection: View {
    @ObservedObject var model: SpikeModel

    var body: some View {
        Section {
            TextField("Device name in the tailnet", text: $model.hostname)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            TextField("Control URL (empty: Tailscale)", text: $model.controlURL)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.URL)
            SecureField("Auth key (optional; used once, not saved)", text: $model.authKey)
            HStack {
                Button("Start") { Task { await model.startNode(cycle: nil) } }
                    .disabled(model.node != nil)
                Spacer()
                Button("Stop") { Task { await model.stopNode(reason: "button") } }
                    .disabled(model.node == nil)
            }
            .buttonStyle(.borderless)
            Button("Log out and delete the node state", role: .destructive) {
                Task { await model.logoutAndDelete() }
            }
        } header: {
            Text("Join the tailnet")
        } footer: {
            Text("Saved node state: \(model.hasState ? "yes" : "no"). Without an auth key the node shows a sign-in button. With device approval on, approve the device in the Tailscale admin console.")
        }
    }
}

struct TargetSection: View {
    @ObservedObject var model: SpikeModel

    var body: some View {
        Section {
            TextField("Mac: 100.x.y.z or name.tailnet.ts.net", text: $model.targetHost)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.URL)
            TextField("Port", text: $model.targetPort)
                .keyboardType(.numberPad)
            Toggle("TLS with a pin (in Rust)", isOn: $model.useTLS)
            if model.useTLS {
                TextField("Pin: base64url or hex SHA-256 (empty: report only)", text: $model.pin)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.caption.monospaced())
            }
            TextField("Path", text: $model.path)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button(model.probing ? "Probing…" : "Dial and probe") {
                Task { await model.probeNow() }
            }
            .disabled(model.probing || !model.upDone)
            if let result = model.lastProbe {
                ProbeView(result: result)
            }
        } header: {
            Text("Target on the Mac")
        } footer: {
            Text("scripts/mac-target.sh on the Mac prints the address, the port, and the pin. The probe dials through the node, then Rust runs TLS over the dialed descriptor and checks the pin.")
        }
    }
}

struct ProbeView: View {
    let result: ProbeResult

    var body: some View {
        LabeledContent("Result", value: result.ok ? "answered" : "failed")
        if !result.error.isEmpty {
            Text(result.error).font(.caption).foregroundStyle(.red)
        }
        LabeledContent("Dial", value: ms(result.dialMs))
        LabeledContent("TLS handshake (after the dial)", value: ms(result.number("handshake_ms")))
        LabeledContent("First byte (after the dial)", value: ms(result.number("first_byte_ms")))
        LabeledContent("Descriptor", value: result.text("fd_kind").isEmpty ? "–" : result.text("fd_kind"))
        if (result.report["tls"] as? Bool) == true {
            LabeledContent("TLS", value: "\(result.text("tls_version")) \(result.text("cipher"))")
            LabeledContent("Pin check", value: result.text("pin_check"))
            Text("Pin seen: \(result.text("pin_seen"))")
                .font(.caption.monospaced())
                .textSelection(.enabled)
        }
        if !result.text("status_line").isEmpty {
            Text(result.text("status_line")).font(.caption.monospaced())
        }
    }
}

struct MeasureSection: View {
    @ObservedObject var model: SpikeModel

    var body: some View {
        Section {
            Picker("When the app is hidden", selection: $model.lifecycle) {
                ForEach(Lifecycle.allCases) { Text($0.label).tag($0) }
            }
            Toggle("Start the node when the app becomes active", isOn: $model.autoStart)
            Toggle("Dial and probe after each start", isOn: $model.autoProbe)
            Toggle("Another VPN is on (set by hand)", isOn: $model.vpnOn)
            LabeledContent("Network", value: model.network)
            Text(model.networkDetail).font(.caption)
            LabeledContent("Tunnels seen", value: model.tunnels.isEmpty ? "none" : model.tunnels)
            Button(model.seriesRunning ? "Stop the series (\(model.seriesStatus))" : "Run 10 cold starts here") {
                model.runSeries(count: 10)
            }
            if !model.seriesRunning && !model.seriesStatus.isEmpty {
                Text(model.seriesStatus).font(.caption)
            }
            ForEach(model.groupedStats()) { row in
                StatRowView(row: row)
            }
            NavigationLink("Samples (\(model.samples.count))") {
                SamplesView(model: model)
            }
            Button("Copy the results") { model.copyResults() }
            Button("Delete the samples", role: .destructive) { model.clearSamples() }
        } header: {
            Text("Measure")
        } footer: {
            Text("A try counts from the app becoming active (or the button) to the first byte of the Mac's answer. \"cold\": the node started from its saved state; \"kept\": the node ran through the hidden time; \"launch\": a new process.")
        }
    }
}

struct StatRowView: View {
    let row: StatRow

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(row.key.network), \(row.key.vpn), \(row.key.kind): \(row.count) tries, \(row.failures) failed")
                .font(.caption.bold())
            Text("up p50 \(ms(row.upP50)), p90 \(ms(row.upP90)); answer p50 \(ms(row.answerP50)), p90 \(ms(row.answerP90))")
                .font(.caption.monospaced())
        }
    }
}

struct SamplesView: View {
    @ObservedObject var model: SpikeModel

    var body: some View {
        List(model.samples) { sample in
            VStack(alignment: .leading, spacing: 2) {
                Text("\(sample.at.formatted(date: .omitted, time: .standard)) \(sample.kind), \(sample.network), VPN \(sample.vpnOn ? "on" : "off")")
                    .font(.caption.bold())
                Text("up \(ms(sample.upMs)), dial \(ms(sample.dialMs)), TLS \(ms(sample.handshakeMs)), answer \(ms(sample.answerMs))")
                    .font(.caption.monospaced())
                if let hidden = sample.secondsHidden {
                    Text(String(format: "hidden %.0f s", hidden)).font(.caption)
                }
                Text(sample.ok ? sample.path : sample.error)
                    .font(.caption)
                    .foregroundStyle(sample.ok ? Color.secondary : Color.red)
            }
        }
        .navigationTitle("Samples")
    }
}

struct ResourcesSection: View {
    @ObservedObject var model: SpikeModel

    var body: some View {
        Section {
            LabeledContent("Footprint now", value: megabytes(model.resources.footprintMB))
            LabeledContent("Footprint peak", value: megabytes(model.resources.peakMB))
            LabeledContent("Resident", value: megabytes(model.resources.residentMB))
            LabeledContent("Threads", value: "\(model.resources.threads)")
            LabeledContent("CPU since launch", value: String(format: "%.1f s", model.resources.cpuSeconds))
            LabeledContent("Go goroutines", value: "\((model.resources.go["goroutines"] as? NSNumber)?.intValue ?? 0)")
            LabeledContent("Go runtime memory", value: megabytes(Double((model.resources.go["sys_bytes"] as? NSNumber)?.int64Value ?? 0) / 1_048_576))
            Button("Measure 5 minutes in the foreground") { model.startCPUWindow() }
            if !model.cpuWindow.isEmpty {
                Text(model.cpuWindow).font(.caption)
            } else if !model.savedCPUWindow.isEmpty {
                Text("Last: \(model.savedCPUWindow)").font(.caption)
            }
            LabeledContent("Executable", value: megabytes(model.executableMB))
            LabeledContent("App bundle", value: megabytes(model.bundleMB))
        } header: {
            Text("Resources")
        } footer: {
            Text("Footprint is what iOS counts against the app's memory limit. The install size for the go/no-go comes from the thinning report and the link map (docs/design/spike-tsnet-ios.md).")
        }
    }
}

struct PrivacySection: View {
    @ObservedObject var model: SpikeModel

    var body: some View {
        Section {
            Text(model.noLogsInfo).font(.caption)
            Button("Ask the LocalAPI over loopback") { Task { await model.checkLocalAPI() } }
                .disabled(model.node == nil)
            if !model.localAPIResult.isEmpty {
                Text(model.localAPIResult).font(.caption)
            }
            Text("State directory: \(model.stateDirInfo)").font(.caption)
            NavigationLink("State files (\(model.stateFiles.count))") {
                List(model.stateFiles) { file in
                    VStack(alignment: .leading) {
                        Text(file.name).font(.caption.monospaced())
                        Text("\(file.size) bytes, \(file.protection)").font(.caption)
                    }
                }
                .navigationTitle("State files")
                .onAppear { model.refreshFiles() }
            }
            NavigationLink("Node log (memory only)") {
                LogView()
            }
            NavigationLink("stderr (this run and the last)") {
                StderrView(model: model)
            }
            Toggle("No logs to Tailscale (next launch)", isOn: $model.noLogsNextLaunch)
            Toggle("stderr to a file (next launch)", isOn: $model.stderrToFileNextLaunch)
        } header: {
            Text("Logs and privacy")
        } footer: {
            Text("Turn \"No logs\" off only as the positive control of the packet log. The node log stays in memory; stderr goes to Library/Caches for the crash tests.")
        }
    }
}

struct LogView: View {
    @State private var lines: [String] = []

    var body: some View {
        List(Array(lines.enumerated().reversed()), id: \.offset) { item in
            Text(item.element).font(.caption2.monospaced())
        }
        .navigationTitle("Node log")
        .toolbar {
            Button("Refresh") { lines = SpikeLog.shared.snapshot() }
        }
        .onAppear { lines = SpikeLog.shared.snapshot() }
    }
}

struct StderrView: View {
    @ObservedObject var model: SpikeModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("This run").font(.headline)
                Text(model.stderrTail.isEmpty ? "(empty)" : model.stderrTail)
                    .font(.caption2.monospaced())
                    .textSelection(.enabled)
                Text("The last run").font(.headline)
                Text(model.previousStderrTail.isEmpty ? "(empty)" : model.previousStderrTail)
                    .font(.caption2.monospaced())
                    .textSelection(.enabled)
            }
            .padding()
        }
        .navigationTitle("stderr")
        .toolbar {
            Button("Refresh") { model.refreshStderr() }
        }
        .onAppear { model.refreshStderr() }
    }
}

struct MoreSection: View {
    @ObservedObject var model: SpikeModel

    var body: some View {
        Section("More") {
            NavigationLink("Crash tests") { CrashView(model: model) }
            NavigationLink("Timeline (\(model.events.count))") {
                List(model.events, id: \.self) { Text($0).font(.caption2.monospaced()) }
                    .navigationTitle("Timeline")
            }
            NavigationLink("Build") { BuildView(model: model) }
        }
    }
}

struct CrashView: View {
    @ObservedObject var model: SpikeModel

    var body: some View {
        Form {
            Section {
                Toggle("Go traceback = crash (abort, with a crash report)", isOn: $model.goTracebackCrash)
                ForEach(CrashKind.allCases) { kind in
                    Button(kind.label, role: .destructive) { model.crash(kind) }
                }
            } header: {
                Text("Each button ends the app")
            } footer: {
                Text("Start the node first, so that both runtimes are busy. After the crash, open the app again and read \"The last crash test\" and stderr of the last run. iOS keeps crash reports in Settings › Privacy & Security › Analytics & Improvements › Analytics Data (TailnetSpike-…).")
            }
            Section("The last crash test") {
                Text(model.lastCrashTest.isEmpty ? "none" : model.lastCrashTest).font(.caption)
                Text(model.previousStderrTail.isEmpty ? "(stderr of the last run is empty)" : model.previousStderrTail)
                    .font(.caption2.monospaced())
                    .lineLimit(40)
                    .textSelection(.enabled)
                Button("Clear the note") { model.clearCrashNote() }
            }
        }
        .navigationTitle("Crash tests")
    }
}

struct BuildView: View {
    @ObservedObject var model: SpikeModel

    var body: some View {
        let pins = model.buildInfo["pins"] as? [String: Any] ?? [:]
        let archives = model.buildInfo["archives"] as? [[String: Any]] ?? []
        return Form {
            Section("Pins") {
                ForEach(pins.keys.sorted(), id: \.self) { key in
                    LabeledContent(key, value: "\(pins[key] ?? "")")
                        .font(.caption)
                }
                LabeledContent("Go", value: model.buildInfo["go"] as? String ?? "?").font(.caption)
                LabeledContent("Rust", value: model.buildInfo["rustc"] as? String ?? "?").font(.caption)
                LabeledContent("Licenses", value: model.buildInfo["licenses"] as? String ?? "?")
                LabeledContent("Built", value: model.buildInfo["built"] as? String ?? "?").font(.caption)
            }
            Section("Archives") {
                ForEach(Array(archives.enumerated()), id: \.offset) { item in
                    let archive = item.element
                    let bytes = (archive["bytes"] as? NSNumber)?.doubleValue ?? 0
                    VStack(alignment: .leading) {
                        Text("\(archive["slice"] as? String ?? "")/\(archive["name"] as? String ?? "")").font(.caption.bold())
                        Text(String(format: "%.1f MB", bytes / 1_000_000)).font(.caption)
                        Text(archive["sha256"] as? String ?? "").font(.caption2.monospaced())
                    }
                }
            }
        }
        .navigationTitle("Build")
    }
}
