# Sync, devices, and plans: flow redesign

Mode: **Improve** (the flow exists). Owner's target, 2026-10-13: the flow in the app follows the plans. Free syncs through iCloud. Paid (personal) and Team (paid) sync through the Apassy relay. Only paid plans have shared vaults, through the relay. Every plan has approvals on any device, through the relay. Reference pattern: T3 Connect in T3 Code ("connect environments").

## Status

| Stage | Status | Artifact |
|---|---|---|
| 0. Preflight | done | this file |
| 1. UX spec: audit, then design | done (draft) | [flow-spec.md](flow-spec.md) |
| Gate A: spec approval | done (2026-10-13) | no account on Free; buy on the Mac in the browser; shared vaults in both paid plans; other folders free under "Other folder…" |
| 2. Component map | done | [component-map.md](component-map.md), [build-plan.md](build-plan.md) |
| 3. Visual direction | done (established theme; hero, peak, ending, upgrade sheet) | [visual-direction.md](visual-direction.md) |
| 4. Build | in progress | F0 foundation done (7ab2e99); S4 relay Connect done in ~/Dev/apassy-relay-connect feat/connect (not deployed); S5 ADR 0027 + contract done; S1 Mac devices and S3 iPhone running; S2 sync picker + plan next |
| 5. Verify | todo | verify-report.md |

## Preflight (Stage 0)

- **Specialist skills.** `uxled-psychology` is present. `frontend-design`, the shadcn skill, and the Design plugin are not installed. They also do not fit: the flow is native UI (egui on the Mac, SwiftUI on the iPhone), not a web app. Degraded mode:
  - Stage 2 maps the spec to the app's own kits (`src/desktop/ui/kit.rs`, `settings_rows.rs`, `detail_rows.rs`; SwiftUI `Form`/`List` on the iPhone), not to shadcn.
  - Stage 3 keeps the established look and only designs the peak and end screens.
  - Stage 5 uses the checklists of the master-product skill (`references/verify.md`).
- **Project state.** shadcn is not used (native app). The approved designs are `docs/design/app-v2-mockup.html` (Mac) and `docs/design/ios-v1-mockup.html` (iPhone).
- **Theme maturity.** Established. No token changes.
- **Runnable.** Yes. The Mac app runs with the screenshot tour (`scripts/screenshots.sh`, synthetic data). The iPhone app runs in the Simulator. Verification uses real screenshots of both.
- **Branch.** `product/sync-plans`, from `feat/low-friction-access` at 5ed5f77.
