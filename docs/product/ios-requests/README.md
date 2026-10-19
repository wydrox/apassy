# iOS Requests — design and implementation

Scope: master-product **Improve**, Audit → Design, with three interactive HTML proposals. Source baseline `46e088dc69cc0d0d77dfad4849984867bd136d44` (0.5.5). Synthetic examples only. Native implementation authorized by “Implementuj (use subagents)”. Source work is on `product/ios-requests`; versions remain 0.5.5. No release, account or real-vault changes.

| Stage | Status |
| --- | --- |
| 0: preflight | done — native SwiftUI, existing blue accent and system typography |
| 1: source audit and proposed flow | complete — source audit, journey, state contract and history gap |
| Gate A: direction selection | A with list actions accepted as wireframe; native Liquid Glass required |
| 2: component mapping | native SwiftUI mapping; shadcn adoption not applicable |
| 3: visual direction | established iOS language; no production token changes |
| 4: implementation | native Waiting / History and list actions implemented and integrated |
| 5: verification | native core/model/contract tests, app build and seven synthetic UI scenarios pass. Earlier HTML checks remain separate evidence |

The user accepted A with list actions as the wireframe and explicitly required master-product, apple-design and swiftui-pro for the native Liquid Glass treatment. The IA direction is settled; HTML styling is not an approved native visual specification. Implementation uses a 30-day, 1,000-entry per-vault encrypted local journal, excluded from backups, with explicit clearing. History covers relay vault requests observed on this iPhone; Wi-Fi companion activity remains separate because it lacks a verified vault association. Native validation is recorded separately from the earlier HTML evidence; no release is claimed.

Specialists: master-product, uxled-psychology, apple-design and swiftui-pro. Frontend-design, shadcn and the legacy `design:*` plugin are absent from the active skill catalog. Fallback: preserve the existing visual language; use master-product's verification checklist and native Apple components. No npm/shadcn initialization or dependencies are relevant to this SwiftUI proposal. Optional installation commands from the skill: `claude plugin install frontend-design@claude-plugins-official`; `pnpm dlx skills add shadcn/ui`; `claude plugin marketplace add anthropics/knowledge-work-plugins` then `claude plugin install design@knowledge-work-plugins`. These were not run.

Current-app findings are **source based**, not device observations. HTML browser screenshots demonstrate only the synthetic proposals. History is implemented on this branch; this does not claim the shipped app contains it.

Artifacts: [flow spec](flow-spec.md), [component map](component-map.md), [visual direction](visual-direction.md), [verification](verify-report.md), [interactive comparison](index.html).

Open any HTML file directly; no installation, network or server is required:

- [A: Waiting / History — recommended](a-waiting-history.html)
- [B: One journal](b-journal.html)
- [C: Vault inboxes](c-vault-inboxes.html)

Use the concept buttons to compare alternatives, use visible list actions or tap a row for full details, or select an edge state in the review controls. All data resets when the document reloads. The files share the same demo and start on different concepts.

The recommended implementation order is: simplify the current queue and empty states; define and implement the encrypted journal; add searchable History and outcome receipts; validate native accessibility and real-device transport/authentication with synthetic fixtures. History must not ship as a relabeled ten-minute cache. Cross-device completeness is a separate data contract.

Revision: list actions added across A/B/C after the user asked for them. Eligible routine rows expose Deny / Allow Once; elevated requests expose Deny / Review. A stable inline receipt prevents another row from jumping into the action position. The accepted behavior is now implemented natively on this branch.

Accepted direction: **A · Waiting / History, with visible list actions**. Follow the Liquid Glass requirements in [visual-direction.md](visual-direction.md#native-liquid-glass-requirement) and the native mapping in [component-map.md](component-map.md#10-native-liquid-glass). B/C remain comparison artifacts, not implementation alternatives awaiting selection.

Native implementation and current checks: [implementation report](implementation-report.md).
