# Visual direction: iOS Requests

Accepted wireframe: A with list actions. Native visual implementation must follow Liquid Glass using master-product, apple-design and swiftui-pro. Preserve the app's native system typography, accent and Vault / Requests / Search navigation. HTML defines hierarchy and behavior; its CSS is not the native visual specification.

## Hierarchy and copy

- One screen title: **Requests**. A stable **Waiting / History** switch in recommended option A.
- Waiting rows expose credential, action, agent/project, vault, environment and real expiry. Eligible list grants also show a meaningful command; full scope and supporting rationale remain available in detail.
- Use **Production** text, not a red dot alone. No urgency animation or countdown pressure.
- Empty waiting: **No requests waiting**, with **View History**. Empty history: **No history yet**. No extra paragraph explaining an obvious empty state.
- Remove persistent Suggestions placeholders and repeated setup guidance from daily use. Connection instructions appear only when connection is needed or intentionally opened.
- History shows dated records, search and a small set of filters. **Seen on this iPhone** makes the proposed first release's coverage honest.
- Keep outcome states that change what the owner can conclude: sending, sent, unconfirmed, confirmed, expired and changed. Remove redundant status narration around those states.

## Visual system

| Element | Prototype treatment | Native translation |
| --- | --- | --- |
| Typography | System stack; 34px screen title, 17px rows/actions, 13px supporting context | Semantic text styles and Dynamic Type, not fixed point sizes |
| Spacing | 16px screen/row insets, 12px internal gaps, 20–22px sections | Native List insets and system spacing |
| Surfaces | Quiet grouped gray, white list surfaces, subtle separators | System grouped backgrounds and native List |
| Action | Blue `#005ec4`, pale blue selection; dark `#72b3ff` | Existing accent and semantic foregrounds, checked in context |
| Status | Neutral until confirmation; green allowed, red denied, amber production, all with text | Semantic colors and accessible labels |
| Interaction | Minimum 44×44 CSS-pixel targets in tested HTML; primary action 50px high | At least 44×44pt native hit regions |
| Motion | No ornamental motion; reduced-motion override | Honor Reduce Motion and native transition behavior |

No illustration, branding refresh, generated asset, new font, dependency or production token change is needed. The HTML's more contrastive blue is a preview choice, not an instruction to overwrite the current AccentColor.

## Alternatives

**A: Waiting / History** is the default recommendation: answering and looking back are distinct jobs, each one tap away. **B: One journal** suits frequent reviewers but adds past records to everyday scanning. **C: Vault inboxes** makes many-vault boundaries explicit but adds an unnecessary step for a single-vault owner.

## Reference basis and limits

The bundled apple-design references for [writing](https://developer.apple.com/design/human-interface-guidelines/writing), [lists and tables](https://developer.apple.com/design/human-interface-guidelines/lists-and-tables), feedback and [tab bars](https://developer.apple.com/design/human-interface-guidelines/tab-bars) informed concise rows, contextual status and stable navigation. Live Apple pages required JavaScript; this review does not claim their full current text was retrieved. swiftui-pro informed the native component map.

This is a design proposal, not a declaration of HIG compliance. VoiceOver, Dynamic Type, safe-area behavior, native authentication and real iPhone interaction remain implementation acceptance work.

## List-action revision

Waiting rows gain two clearly separated, equally reachable controls. Deny uses a restrained red label; Allow Once or Review uses blue. Supporting identity/scope is shown before the controls. Full details remain a distinct navigation target. Completed rows temporarily keep their position and expose Done; no new full-screen success step is necessary. Larger-text mode stacks controls.

## Native Liquid Glass requirement

This is a user requirement for implementation, not optional polish. Use master-product for flow/coherence, apple-design for HIG/material review, and swiftui-pro for native SwiftUI structure and behavior. Preserve existing deployment and toolchain settings.

- Prefer system `TabView`, `NavigationStack`, toolbars, segmented picker, search, sheets and buttons so the OS supplies their appearance and interaction. Do not reproduce the HTML tab capsule, borders, blur or corner radii by hand.
- Keep Liquid Glass in the floating navigation/control layer. Request rows, commands, history entries and receipt content use readable system content surfaces. Do not add glass to every card or stack translucent panels.
- Let content scroll beneath system bars with the native scroll-edge treatment and correct safe areas. Do not paint an opaque custom toolbar background over the system material or cover actionable content.
- Use standard native button styles for repeated in-row actions, with clear roles and restrained emphasis. Do not turn every Allow Once into a prominent tinted glass button. Reserve prominent treatment for the principal action in a focused review context; refusal remains equally reachable.
- Use custom glass only if a necessary floating control cannot use a standard component. Prefer the regular variant for this text-heavy utility; clear glass is not the default for request review.
- Use semantic colors/type and native shapes. Validate Dynamic Type, VoiceOver, 44pt targets, light/dark appearance, Reduce Transparency, Increase Contrast and Reduce Motion. Respect the system's material preferences.
- Native screenshots and interaction checks must cover populated/empty lists, list actions, review, history, authentication return and confirmation, both at rest and while scrolling. HTML blur or screenshot resemblance cannot prove native compliance.

Basis: apple-design `liquid-glass.md › The two layers`, `Where the material belongs`, `Color on glass` and `Review checklist`; swiftui-pro `design.md › Standard system styling` and accessibility guidance. Primary references: [Apple Materials](https://developer.apple.com/design/human-interface-guidelines/materials) and [Adopting Liquid Glass](https://developer.apple.com/documentation/technologyoverviews/adopting-liquid-glass). Native verification has not yet been performed.
