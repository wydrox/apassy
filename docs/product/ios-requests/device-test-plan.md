# Requests A: TestFlight device check

Use synthetic credentials in a test vault. This checklist covers device behavior that the local model, core and Simulator checks cannot establish.

1. **Face ID — approval and cancellation.** For a current, fully described non-production Read request, choose Allow Once from Waiting. Confirm that real owner authentication is required. Cancel once: the same request remains in place, without a sent/allowed receipt. Authenticate again: verify the exact credential, vault and requesting Mac. Production or unclear requests must offer Review instead of a quick grant.
2. **Face ID — interrupted or changed requests.** While authentication is visible, lock/background the app, expire/change the request, or change the active vault/pairing. Returning must not approve a different request or restore locked history. A canceled or failed authentication grants no authority.
3. **APNs — foreground, background and cold launch.** From a connected test Mac, trigger a fresh request in each state. The notification contains generic text, without credential names, secrets or command details. Opening it returns to Waiting and refreshes; it must not select an unrelated newer request or unlock a vault automatically. Repeat with notification permission denied and a temporarily offline phone.
4. **Delivery and confirmation.** Check normal acceptance, lost network response and reconnect. “Sent” or an attempted answer must not become “Allowed” without the authoritative confirmation. Restart during an uncertain answer and verify that a different answer cannot bypass its pending guard.
5. **History.** Search and filter confirmed and unconfirmed requests. Lock/unlock the vault, then verify hiding/restoration. Clear a named vault's history; a live unresolved answer guard must remain protected. History covers relay vault requests observed on this iPhone, not complete cross-device/Wi-Fi activity.
6. **Accessibility.** Complete one review, one denial and a history lookup with VoiceOver and the largest text size. Verify readable light/dark appearance and reachable separate navigation/action targets.

Record the exact TestFlight version/build, iPhone model, iOS version and observed result. A successful upload or `IN_BETA_TESTING` state does not prove Face ID, APNs delivery or installation on this device.
