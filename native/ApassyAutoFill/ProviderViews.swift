// The sheet of the extension. Text from a website or the vault is shown through
// visibleText (no control or bidi characters).

import SwiftUI

struct ProviderRootView: View {
    @ObservedObject var model: ProviderModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Apassy", systemImage: "key.viewfinder")
                .font(.headline)
            content
        }
        .padding(20)
        .frame(minWidth: 420, idealWidth: 440, minHeight: 300, idealHeight: 380, alignment: .topLeading)
    }

    @ViewBuilder
    private var content: some View {
        switch model.screen {
        case .connecting:
            Status(text: "Connecting to Apassy…", busy: true)
            footer(cancel: true)
        case .waiting(let locked):
            Status(
                text: locked
                    ? "Unlock your vault in Apassy. AutoFill goes on when the vault is open."
                    : "Open Apassy and unlock your vault. AutoFill goes on when Apassy is ready.",
                busy: true)
            HStack {
                Button("Open Apassy") { model.openApassy() }
                Spacer()
                Button("Cancel", role: .cancel) { model.cancel() }
                    .keyboardShortcut(.cancelAction)
            }
        case .choose(let choices):
            ChoiceList(model: model, choices: choices)
        case .register(let form):
            RegisterForm(model: model, form: form)
        case .confirm(let text):
            Status(text: text, busy: true)
            Text("Confirm in Apassy. Apassy asks for Touch ID or your passphrase.")
                .foregroundStyle(.secondary)
            HStack {
                Button("Show Apassy") { model.openApassy() }
                Spacer()
                Button("Cancel", role: .cancel) { model.cancel() }
                    .keyboardShortcut(.cancelAction)
            }
        case .configured(let text):
            Status(text: text, busy: false)
            HStack {
                Spacer()
                Button("Done") { model.doneConfiguring() }
                    .keyboardShortcut(.defaultAction)
            }
        case .problem(let text):
            Status(text: text, busy: false)
            HStack {
                Spacer()
                Button("Close") { model.closeProblem() }
                    .keyboardShortcut(.defaultAction)
            }
        }
    }

    private func footer(cancel: Bool) -> some View {
        HStack {
            Spacer()
            Button("Cancel", role: .cancel) { model.cancel() }
                .keyboardShortcut(.cancelAction)
        }
    }
}

private struct Status: View {
    let text: String
    let busy: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            if busy {
                ProgressView().controlSize(.small)
            }
            Text(text)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct ChoiceList: View {
    @ObservedObject var model: ProviderModel
    let choices: Choices

    private var loginKind: ChoiceKind {
        choices.kind == .oneTimeCode ? .oneTimeCode : .password
    }

    var body: some View {
        Text(heading)
            .foregroundStyle(.secondary)
        List {
            if !choices.passkeys.isEmpty {
                Section("Passkeys") {
                    ForEach(choices.passkeys) { passkey in
                        Button { model.choose(passkey: passkey) } label: {
                            Row(icon: "person.badge.key", title: passkey.userName.isEmpty ? passkey.title : passkey.userName, detail: passkey.title)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            if !choices.matches.isEmpty {
                Section(choices.kind == .passkey ? "Passwords" : "For this website") {
                    ForEach(choices.matches) { login in loginRow(login) }
                }
            }
            if !choices.others.isEmpty {
                Section {
                    if model.showAllLogins {
                        ForEach(choices.others) { login in loginRow(login) }
                    } else {
                        Button("Show all logins (\(choices.others.count))") { model.showAllLogins = true }
                    }
                }
            }
        }
        .frame(minHeight: 180)
        HStack {
            Spacer()
            Button("Cancel", role: .cancel) { model.cancel() }
                .keyboardShortcut(.cancelAction)
        }
    }

    private var heading: String {
        let empty = choices.passkeys.isEmpty && choices.matches.isEmpty && choices.others.isEmpty
        if empty {
            return choices.kind == .oneTimeCode
                ? "Apassy has no login with a one-time code."
                : "Apassy has no passkey or login for \(choices.site)."
        }
        switch choices.kind {
        case .passkey: return "Sign in to \(choices.site)"
        case .oneTimeCode: return "Fill a one-time code"
        case .password: return choices.site.isEmpty ? "Fill a password" : "Fill a password for \(choices.site)"
        }
    }

    private func loginRow(_ login: LoginChoice) -> some View {
        Button { model.choose(login: login, kind: loginKind) } label: {
            Row(icon: loginKind == .oneTimeCode ? "clock" : "key", title: login.title, detail: login.username)
        }
        .buttonStyle(.plain)
    }
}

private struct Row: View {
    let icon: String
    let title: String
    let detail: String

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).lineLimit(1)
                if !detail.isEmpty, detail != title {
                    Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer()
        }
        .contentShape(Rectangle())
    }
}

private struct RegisterForm: View {
    @ObservedObject var model: ProviderModel
    let form: RegistrationForm

    var body: some View {
        Text("Save a passkey for \(form.account.isEmpty ? "this account" : form.account) on \(form.site)?")
            .fixedSize(horizontal: false, vertical: true)
        Text("The website named the account. Apassy keeps the key and asks for Touch ID or your passphrase before it saves.")
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
        Picker("Save in", selection: $model.attachTarget) {
            Text("A new login").tag(UInt64?.none)
            ForEach(form.attachable) { login in
                Text(login.username.isEmpty ? login.title : "\(login.title) (\(login.username))").tag(UInt64?.some(login.id))
            }
        }
        if model.attachTarget == nil {
            TextField("Name", text: $model.newTitle)
        }
        Spacer()
        HStack {
            Spacer()
            Button("Cancel", role: .cancel) { model.cancel() }
                .keyboardShortcut(.cancelAction)
            Button("Save in Apassy") { model.saveRegistration() }
                .keyboardShortcut(.defaultAction)
        }
    }
}
