import Foundation
import Testing

@testable import ApassyVaultKit

/// The models of a vault on a node (contract node-pairing-v1, ios-core-v1 sections 5.2, 5.10, and
/// 6; plan S2–S3 unit N6): the pin, the alternatives, and the name of a `phone.json` entry, the
/// `node` of a join and of a questions status, and the new error codes. Synthetic values only.
@Suite("Node models")
struct NodeModelsTests {
    static let pin = "u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE"

    @Test("an entry of a node keeps its pin, alternatives, and name; an older entry has none")
    func vaultEntry() throws {
        let node = #"{"id":"4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c","name":"Personal","sync_source":null,"relay_url":"https://100.64.0.7:8444","team_id":"t_7k2m5q4x3c","device_id":3,"added_at":1,"pin":"\#(Self.pin)","alt":["apassy-mini.tail0123.ts.net:8444"],"node_name":"Mac mini"}"#
        let entry = try JSONDecoder().decode(VaultEntry.self, from: Data(node.utf8))
        #expect(entry.pin == Self.pin)
        #expect(entry.alt == ["apassy-mini.tail0123.ts.net:8444"])
        #expect(entry.nodeName == "Mac mini")
        #expect(entry.isRelay && entry.isNode)
        let again = try JSONDecoder().decode(VaultEntry.self, from: try JSONEncoder().encode(entry))
        #expect(again == entry)

        let old = #"{"id":"4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c","name":"Personal","relay_url":"https://apassy-relay.wyderka.cc","team_id":"t_7k2m5q4x3c","device_id":3,"added_at":1}"#
        let hosted = try JSONDecoder().decode(VaultEntry.self, from: Data(old.utf8))
        #expect(hosted.pin == nil && hosted.alt.isEmpty && hosted.nodeName == nil)
        #expect(hosted.isRelay && !hosted.isNode)
        // A hosted entry writes none of the node keys.
        let written = String(decoding: try JSONEncoder().encode(hosted), as: UTF8.self)
        #expect(!written.contains("\"pin\"") && !written.contains("\"alt\"") && !written.contains("node_name"))

        // An iCloud vault is never a node.
        let icloud = VaultEntry(id: "a", name: "A", relayURL: nil, teamID: nil, deviceID: nil, addedAt: 1, syncSource: "icloud")
        #expect(!icloud.isNode)
    }

    @Test("a join of a pinned link names its node; a hosted join has none")
    func joinNode() throws {
        let pinned = #"{"state":"waiting","team":"Personal","words":["amber","marble"],"expires_at":1791200600,"node":{"origin":"https://100.64.0.7:8444","name":"Mac mini"}}"#
        let join = try JSONDecoder().decode(JoinInfo.self, from: Data(pinned.utf8))
        #expect(join.node == NodeInfo(origin: "https://100.64.0.7:8444", name: "Mac mini"))
        let unnamed = #"{"state":"waiting","team":"Personal","words":["amber","marble"],"expires_at":1791200600,"node":{"origin":"https://100.64.0.7:8444"}}"#
        #expect(try JSONDecoder().decode(JoinInfo.self, from: Data(unnamed.utf8)).node?.name == nil)
        let hosted = #"{"state":"ready","team":"Personal","words":["amber","marble"],"expires_at":1791200600}"#
        #expect(try JSONDecoder().decode(JoinInfo.self, from: Data(hosted.utf8)).node == nil)
    }

    @Test("a questions status of a team on a node names the origin; another status has no node")
    func statusNode() throws {
        let node = #"{"enabled":true,"team_id":"t_7k2m5q4x3c","relay_device_id":3,"device_uuid":null,"answer_key":null,"has_key":true,"registered":false,"removed":false,"node":{"origin":"https://100.64.0.7:8444"}}"#
        let status = try JSONDecoder().decode(QuestionsStatus.self, from: Data(node.utf8))
        #expect(status.node == NodeInfo(origin: "https://100.64.0.7:8444"))
        #expect(try JSONDecoder().decode(QuestionsStatus.self, from: try JSONEncoder().encode(status)) == status)
        let hosted = #"{"enabled":true,"team_id":"t_7k2m5q4x3c","has_key":true,"registered":true,"removed":false}"#
        #expect(try JSONDecoder().decode(QuestionsStatus.self, from: Data(hosted.utf8)).node == nil)
        // A node that this app cannot read leaves the status readable.
        let odd = #"{"enabled":true,"has_key":true,"node":{"where":1}}"#
        let read = try JSONDecoder().decode(QuestionsStatus.self, from: Data(odd.utf8))
        #expect(read.enabled && read.node == nil)
    }

    @Test("the codes of a node and of the push gateway read")
    func codes() {
        #expect(VaultError.Code(rawValue: "pin_mismatch") == .pinMismatch)
        #expect(VaultError.Code(rawValue: "link_invalid") == .linkInvalid)
        #expect(VaultError.Code(rawValue: "push_gateway_unreachable") == .pushGatewayUnreachable)
        #expect(VaultError.Code(rawValue: "push_gateway_refused") == .pushGatewayRefused)
    }

    @Test("the preview reads a pinned link as the core: origin, pin, and the decoded name")
    func previewNode() {
        let code = "apassy_lnk_t_7k2m5q4x3c_" + String(repeating: "0123456789abcdef", count: 4)
        let (node, pin) = PreviewVaultService.node(of: "https://100.64.0.7:8444/link#\(code)&pin=\(Self.pin)&name=Mac%20mini")
        #expect(node == NodeInfo(origin: "https://100.64.0.7:8444", name: "Mac mini"))
        #expect(pin == Self.pin)
        let (hosted, none) = PreviewVaultService.node(of: "https://apassy-relay.wyderka.cc/link#\(code)")
        #expect(hosted == nil && none == nil)
    }
}
