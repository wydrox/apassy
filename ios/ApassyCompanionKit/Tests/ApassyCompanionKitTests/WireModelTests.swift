import Foundation
import Testing

@testable import ApassyCompanionKit

@Suite("Wire models")
struct WireModelTests {
    static let inboxJSON = """
        {
          "runs": [
            {
              "id": "123456789012345",
              "agent": "claude-code",
              "command": ["npm", "run", "migrate"],
              "cwd": "/Users/me/Dev/shop",
              "env_names": ["DATABASE_URL"],
              "purpose": "Apply the new migration.",
              "risk": "production credential: always asks the owner",
              "user_request": "Deploy the new schema to staging.",
              "request_source": "from the host hook",
              "agent_request": "",
              "remember": {"pattern": "npm run migrate", "approvals": 1, "needed": 3},
              "digest": "\(String(repeating: "ab", count: 32))",
              "waiting_seconds": 12
            }
          ],
          "access_requests": [
            {"id": "42", "agent": "codex", "item_name": "Stripe test key", "reason": "The user asked me to test checkout.", "cwd": "/Users/me/Dev/shop", "requested_at": 1790000000}
          ],
          "activity": [
            {"id": "991", "at": 1790000000, "agent": "claude-code", "decision": "deny", "summary": "stripe charges list", "reason": "The command prints a secret."}
          ]
        }
        """

    @Test("the inbox example decodes")
    func inbox() throws {
        let inbox = try JSONDecoder().decode(Inbox.self, from: Data(Self.inboxJSON.utf8))
        #expect(inbox.runs.count == 1)
        let run = inbox.runs[0]
        #expect(run.id == "123456789012345")
        #expect(run.agent == "claude-code")
        #expect(run.command == ["npm", "run", "migrate"])
        #expect(run.cwd == "/Users/me/Dev/shop")
        #expect(run.envNames == ["DATABASE_URL"])
        #expect(run.purpose == "Apply the new migration.")
        #expect(run.risk == "production credential: always asks the owner")
        #expect(run.userRequest == "Deploy the new schema to staging.")
        #expect(run.requestSource == "from the host hook")
        #expect(run.agentRequest == "")
        #expect(run.remember == RememberOffer(pattern: "npm run migrate", approvals: 1, needed: 3))
        #expect(run.digest == String(repeating: "ab", count: 32))
        #expect(run.waitingSeconds == 12)

        #expect(inbox.accessRequests == [
            AccessRequest(
                id: "42", agent: "codex", itemName: "Stripe test key", reason: "The user asked me to test checkout.",
                cwd: "/Users/me/Dev/shop", requestedAt: 1_790_000_000)
        ])
        #expect(inbox.activity == [
            ActivityEntry(
                id: "991", at: 1_790_000_000, agent: "claude-code", decision: "deny",
                summary: "stripe charges list", reason: "The command prints a secret.")
        ])
    }

    @Test("remember, waiting_seconds, and cwd can be null or missing")
    func optionalFields() throws {
        let json = """
            {"runs":[{"id":"1","agent":"a","command":["ls"],"cwd":null,"env_names":[],"purpose":"","risk":"",
            "user_request":"","request_source":"","agent_request":"","remember":null,"digest":"\(String(repeating: "0", count: 64))"}],
            "access_requests":[{"id":"2","agent":"a","item_name":"i","reason":"r","cwd":null,"requested_at":5}],
            "activity":[]}
            """
        let inbox = try JSONDecoder().decode(Inbox.self, from: Data(json.utf8))
        #expect(inbox.runs[0].cwd == nil)
        #expect(inbox.runs[0].remember == nil)
        #expect(inbox.runs[0].waitingSeconds == nil)
        #expect(inbox.accessRequests[0].cwd == nil)

        let missing = """
            {"runs":[{"id":"1","agent":"a","command":[],"env_names":[],"purpose":"","risk":"",
            "user_request":"","request_source":"","agent_request":"","digest":"x"}],"access_requests":[],"activity":[]}
            """
        let second = try JSONDecoder().decode(Inbox.self, from: Data(missing.utf8))
        #expect(second.runs[0].cwd == nil)
        #expect(second.runs[0].remember == nil)
    }

    @Test("unknown fields in a response are ignored")
    func unknownFields() throws {
        let json = """
            {"runs":[],"access_requests":[],"activity":[],"future":{"a":1},
             "x":[1,2]}
            """
        let inbox = try JSONDecoder().decode(Inbox.self, from: Data(json.utf8))
        #expect(inbox.runs.isEmpty)

        let status = """
            {"v":1,"mac_name":"Mac mini","app_version":"0.2.1","approval_timeout_seconds":120,"new_field":true,"device":{"id":"d4c0ffee00000000000000000000beef","name":"Test iPhone","paired_at":1790000000,"more":1}}
            """
        #expect(try JSONDecoder().decode(StatusInfo.self, from: Data(status.utf8)).macName == "Mac mini")
    }

    @Test("IDs are strings: a number is refused")
    func idsAreStrings() {
        let json = #"{"runs":[{"id":123,"agent":"a","command":[],"env_names":[],"purpose":"","risk":"","user_request":"","request_source":"","agent_request":"","digest":"x"}],"access_requests":[],"activity":[]}"#
        #expect(throws: DecodingError.self) { try JSONDecoder().decode(Inbox.self, from: Data(json.utf8)) }
    }

    @Test("the status example decodes")
    func status() throws {
        let json = """
            {"v":1,"mac_name":"Mac mini","app_version":"0.2.1","approval_timeout_seconds":120,"device":{"id":"d4c0ffee00000000000000000000beef","name":"Test iPhone","paired_at":1790000000}}
            """
        let status = try JSONDecoder().decode(StatusInfo.self, from: Data(json.utf8))
        #expect(status.v == 1)
        #expect(status.macName == "Mac mini")
        #expect(status.appVersion == "0.2.1")
        #expect(status.approvalTimeoutSeconds == 120)
        #expect(status.device.id == Vectors.deviceID)
        #expect(status.device.name == "Test iPhone")
        #expect(status.device.pairedAt == 1_790_000_000)
    }

    @Test("the pair and pair status examples decode")
    func pairing() throws {
        let response = try JSONDecoder().decode(PairResponse.self, from: Data(#"{"expires_at":1790000300}"#.utf8))
        #expect(response.expiresAt == 1_790_000_300)

        func state(_ json: String) throws -> PairState? {
            try JSONDecoder().decode(PairStatusResponse.self, from: Data(json.utf8)).pairState
        }
        #expect(try state(#"{"state":"waiting"}"#) == .waiting)
        #expect(try state(#"{"state":"paired","mac_name":"Mac mini"}"#) == .paired(macName: "Mac mini"))
        #expect(try state(#"{"state":"denied"}"#) == .denied)
        #expect(try state(#"{"state":"expired"}"#) == .expired)
        #expect(try state(#"{"state":"paired"}"#) == nil)
        #expect(try state(#"{"state":"later"}"#) == nil)
    }

    @Test("the outcomes decode")
    func outcomes() throws {
        #expect(try JSONDecoder().decode(ApproveOutcome.self, from: Data(#""approved""#.utf8)) == .approved)
        #expect(
            try JSONDecoder().decode(ApproveOutcome.self, from: Data(#""approved_and_remembered""#.utf8))
                == .approvedAndRemembered)
        #expect(throws: DecodingError.self) { try JSONDecoder().decode(ApproveOutcome.self, from: Data(#""maybe""#.utf8)) }
    }

    @Test("the pair request has exactly the fields of the contract")
    func pairRequestBody() throws {
        let body = PairRequestBody(
            deviceID: Vectors.deviceID, deviceName: "Test iPhone", requestKey: "rk", approvalKey: "ak",
            requestKeySignature: "rs", approvalKeySignature: "as", proof: "pp")
        let object = try #require(
            JSONSerialization.jsonObject(with: CompanionClient.encode(body)) as? [String: Any])
        #expect(
            Set(object.keys) == [
                "v", "device_id", "device_name", "request_key", "approval_key", "request_key_signature",
                "approval_key_signature", "proof",
            ])
        #expect(object["v"] as? Int == 1)
        #expect(object["device_id"] as? String == Vectors.deviceID)
    }

    @Test("the approve request has exactly the fields of the contract, with remember as a boolean")
    func approveRequestBody() throws {
        let body = ApproveRequestBody(digest: Vectors.approvalDigest, remember: false, time: 1_790_000_000, approvalSignature: "sig")
        let data = try CompanionClient.encode(body)
        let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(object.keys) == ["digest", "remember", "time", "approval_signature"])
        #expect(object["remember"] as? Bool == false)
        #expect(object["time"] as? Int == 1_790_000_000)
    }

    @Test("a device name with a slash is not escaped")
    func slashNotEscaped() throws {
        let body = PairRequestBody(
            deviceID: "d", deviceName: "a/b", requestKey: "", approvalKey: "", requestKeySignature: "",
            approvalKeySignature: "", proof: "")
        let text = String(decoding: try CompanionClient.encode(body), as: UTF8.self)
        #expect(text.contains(#""device_name":"a/b""#))
    }
}
