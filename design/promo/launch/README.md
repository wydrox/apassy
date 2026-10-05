# apassy launch video and shorts

A 69-second launch video in two formats, and a 14-second social short ("3:07am") in two
more. Everything is code: the picture is an HTML page with a deterministic timeline, and
the sound track is synthesized in Node. There are no stock clips, samples, or licensed music.
Frames are drawn by Helium (`/Applications/Helium.app`, Chromium) through Playwright.

| File | Format | Post it on |
| --- | --- | --- |
| `out/apassy-launch.mp4` | 16:9, 1920×1080 | X, YouTube, LinkedIn, the website |
| `out/apassy-launch-9x16.mp4` | 9:16, 1080×1920 | Instagram Reels, TikTok, YouTube Shorts, Threads, stories |
| `out/apassy-cover-9x16.jpg`, `out/apassy-cover-16x9.jpg` | the end card | the cover, where a platform lets you pick one |
| `out/apassy-3am-9x16.mp4` | 9:16, 1080×1920, 14.4 s | Reels, TikTok, Shorts, Threads |
| `out/apassy-3am-4x5.mp4` | 4:5, 1080×1350, 14.4 s | the X, Threads, and LinkedIn feeds |
| `out/apassy-3am-cover-9x16.jpg`, `out/apassy-3am-cover-4x5.jpg` | the opening | the cover of the short |

Both are H.264 + AAC at `-14 LUFS` and share one sound track. The 9:16 version is its own
layout, not a crop: its content stays between y 250 and 1500, clear of the Reels and TikTok
overlays at the top and bottom.

## Commands

Run them in this folder. Playwright comes from `../node_modules`; the browser is Helium. All
times are real seconds of the film.

| Command | What it does |
| --- | --- |
| `node preview.mjs` | Serves the page. Open the address it prints. Space plays with sound, ← → step a frame, Shift+← → step a second, `?t=12.5` opens at a time. |
| `node render.mjs --cues && node audio.mjs` | Exports the sound cues of the page, then synthesizes `out/audio.wav`. |
| `node render.mjs` | Renders the video (4 motion-blur sub-frames per frame) and muxes `out/audio.wav`. |
| `node render.mjs --format tall` | Renders the 9:16 version. `--format tall` works with every command below; the preview takes `?format=tall`. |
| `node render.mjs --film 3am --format tall --cues && node audio.mjs --film 3am && node render.mjs --film 3am --format tall` | The short, 9:16. Use `--format feed` for 4:5. The preview takes `?film=3am&format=tall`. |
| `node render.mjs --mux` | Puts a new `out/audio.wav` into the rendered video, without new frames. |
| `node render.mjs --fps 30 --mb 1 --scale 0.5 --preset veryfast --out draft.mp4` | A fast draft. |
| `node render.mjs --stills 11,26.5` / `--sheet 15,20,0.25` | JPEG stills or a contact sheet in `out/`. |

Useful render options: `--workers N` (parallel browsers; each needs about 1 GB of memory),
`--from 15 --to 20` (a part), `--crf 17` (quality), `--silent` (no audio).

## Design

Light and quiet, in the manner of Apple's product films: one flat canvas (`#f5f5f7`), white
surfaces with soft shadows, SF Pro Display semibold, and one accent, the blue of the logo.
Green, orange, and red appear only for a state (runs, asks, blocked). Motion is calm: short
rises and fades, no blur, glow, particles, shakes, or flashes. The one dark moment is the cut
to black before the drop. The tokens are at the top of `css/base.css`.

Each scene has both layouts. `pick(wide, tall)` (in `js/engine.js`) chooses a value for the
format, and `css/tall.css` holds the styles that differ in 9:16. The timing is the same in
both formats, so the cues and the music are shared.

The logo is in `js/logo.js`: the mark (an archway with an open door) is built from its
geometry, and the wordmark (`js/wordmark.js`) is traced from the brand artwork, with the
straight edges of the y made exact. On screen the door swings open, the mark slides into
place, and the name rises. `iconSVG()` draws the app icon, dark or light. The same shapes
are in `logo/` as SVG files (the mark, the lockup, and both app icons).

## The edit

The scenes and the music are written on a 120 BPM grid (a bar is 2 grid seconds, see
`js/timeline.js`). The film plays `PACE` = 1.25 times slower: 96 BPM, a bar is 2.5 s.
Change `PACE` to change the tempo of the whole film; picture, cues, and music follow.

| Time | Scene | File |
| --- | --- | --- |
| 0–10 s | Hook: your agent has every key, then what can go wrong (prompt injection, secrets sent out, production wiped, key in the logs), a cut to black, "Meet" | `js/scenes/hook.js` |
| 10–15 s | The drop: the logo, its door opens, the tagline | `reveal.js` |
| 15–20 s | One vault for every secret: the Credentials view | `vault.js` |
| 20–27.5 s | The agent holds a placeholder; the apassy proxy puts the real key only into requests to its hosts; `paste.sh` gets `403` | `placeholder.js` |
| 27.5–32.5 s | Rules in plain English: the process access sheet with the instruction and the hard limits | `rules.js` |
| 32.5–40 s | The bouncer sorts seven requests into Runs, Asks you, and Blocked | `bouncer.js` |
| 40–47.5 s | When in doubt, it asks you: notification, approval card, Deny on the beat | `approval.js` |
| 47.5–52.5 s | It learns what is normal: the Learning view | `learning.js` |
| 52.5–60 s | The blind held-out results, then Claude Code and Codex | `proof.js` |
| 60–69 s | "Agents get access. Never your secrets." and the lockup with the call to action | `outro.js` |

## Where the claims come from

- 0 violations and 0 critical cases ran without the owner, and 76% of normal cases ran
  without a prompt on the first day: the blind held-out set v4 (226 cases), in the main
  README and `docs/evaluation/heldout-v4.md`.
- Placeholders and the run proxy: ADR 0011. Rules, hard limits, and the bouncer: ADR 0007.
  A production run always waits for the owner: ADR 0010.
- The app screens follow `src/desktop/ui/` (tokens from `kit.rs`, labels from the views).
  The Learning numbers and chart are demo data.

## Change things

- The call to action and the line under it: `CTA` and `SUB` in `js/scenes/outro.js`.
- Copy: each scene builds its text in `build()`. `*word*` in a headline gets the accent
  blue, `[red:word]` a color class.
- The background: `FX.bg(time, color)` keys (the hook cuts to black; the reveal cuts back).
- Sound: each scene registers `cue(time, type, params)` next to its animation, in grid
  seconds. The types are the functions in `FX` in `audio.mjs`. The music arrangement is in
  the "arrangement" section of `audio.mjs`.

## The 3:07am short

`js/shorts/3am.js`, styles in `css/shorts.css`, music in `arrange3am()` of `audio.mjs`.
Made for social from the start: the hook is on the first frame, the copy is lowercase and
conversational, and it loops. 100 BPM, a bar is 2.4 s.

| Time | Beat |
| --- | --- |
| 0–2.4 s | "POV: it's 3:07am" / "your agent is 'just fixing one migration'". The agent types `npm run db:reset`; the database is production. |
| 2.4–4.8 s | A notification (the agent and the event, never the command). "prod runs wait for you." The agent's line: "Waiting for the owner…" |
| 4.8–7.2 s | "you're asleep." → "so nothing runs." Everything dims except the line that waits. |
| 7.2–9.6 s | The lights come up: "8:02am. prod is fine." |
| 9.6–14.4 s | The logo, "the bouncer for your AI agents.", the call to action. |

The claims: a run with a production item always waits for the owner, and a notification
shows only the agent and the event type (ADR 0010).
