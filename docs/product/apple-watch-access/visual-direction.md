# Visual direction: Apple Watch access requests

**Theme: established.** The watch uses the iPhone app's language: system typography (SF Compact on
watchOS), the same blue `AccentColor` (sRGB 0, 0.478, 1), and the same app icon. No new tokens. Per
master-product, Stage 3 for an established theme designs only the peak and the end, using what exists.

**The point of view is a quiet utility on purpose.** The one thing it is remembered by is that the
watch shows every scope fact before the two answers, and nothing pushes the owner toward Allow. The
boldness is spent in one place: Allow once is the only prominent element, and only when the scope is
complete.

## Peak and end

| Moment | Treatment |
| --- | --- |
| Setup peak (S5 "Connected") | `checkmark.circle.fill` in green next to the headline, one sentence of what the watch does and one of what it does not, a full-width prominent **Done**. No animation and no confetti: this is a security product |
| Answer end (A4) | A checkmark or cross, the past tense outcome ("Allowed once" / "Denied"), the real deadline, "The bouncer still checks the command and may ask you", and "Answered on This watch", followed by **Done**. A success haptic, the same for both outcomes |
| Not confirmed (negative peak) | Neutral text that names the Mac and what to do. There is no red alarm and no automatic retry |

## Color and contrast

- **Text:** system `primary` and `secondary` on black. Secondary text stays at least `.secondary`, never a
  lighter custom gray.
- **Environment:** "Production" is a bold text label. Color never carries meaning alone.
- **Buttons:**
  - Allow once uses the accent fill.
  - Deny uses the system destructive role (red text on the bordered capsule).
  - Disabled buttons use the system unavailable appearance; they are not removed (Always On HIG).

## Layout

- System margins come from `.scenePadding(.horizontal)` in every scrolling screen. Before this fix the
  text touched the screen edges (found in Stage 5).
- Full-width buttons are separated by spacing, with Deny never directly under the finger after Allow once.
- Long hosts and folders wrap. The Digital Crown scrolls; nothing is truncated.
