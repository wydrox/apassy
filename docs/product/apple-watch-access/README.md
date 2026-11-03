# Apple Watch: answer access requests

Mode: master-product **Build**. Branch `feat/apple-watch-access`, based on `origin/main` `4fd3f9fc`.

Owner decisions (2026-11-03):

- the watch is independent, with its own relay membership;
- it answers **access requests only** (ADR 0033);
- **Allow once** works while the watch is unlocked on the wrist;
- arm64 watches only.

The owner also required master-product, apple-design, and swiftui-pro.

| Stage | Status |
| --- | --- |
| 0: preflight | done. Native SwiftUI (watchOS); the existing Apassy blue accent and system type. The shadcn, frontend-design, and `design:*` specialists are absent or not applicable, so the run is degraded: native Apple components and the master-product verify checklist. The watchOS 27 Simulator runtime is installed. |
| 1: UX spec | done: [flow-spec.md](flow-spec.md) |
| Gate A: spec approval | awaiting owner approval |
| 2: component map (native SwiftUI) | todo |
| 3: visual direction (established theme: peak and end screens only) | todo |
| 4: build | todo |
| 5: verify | todo |

The watchOS HIG sections are missing from the apple-design skill's references (the skill leaves out
watchOS-only guidance). Quotes in the spec come from Apple's HIG JSON
(`developer.apple.com/tutorials/data/design/human-interface-guidelines/<page>.json`), fetched on 2026-11-03.
