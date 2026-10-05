// The edit on a 120 BPM grid: one bar is 2 grid seconds. The scenes and the music are
// written in grid seconds; the film plays PACE times slower (96 BPM, a bar is 2.5 s), so
// every time below is multiplied by PACE on screen and in the audio track (audio.mjs).

export const PACE = 1.25;

export const T = {
  hook: 0, // "Your AI agent has your keys." → .env → "What could go wrong?" → montage
  gap: 7, // black and silence before the drop
  reveal: 8, // the drop: the logo
  vault: 12, // one vault for every secret
  placeholder: 16, // the agent never sees the real key
  rules: 22, // rules in plain English
  bouncer: 26, // a bouncer checks every request
  approval: 32, // uncertain → it asks you; Deny on 35
  learning: 38, // it learns what is normal
  proof: 42, // measured numbers, works with Claude Code and Codex
  outro: 48, // Agents get access. Never your secrets.
  lockup: 50, // logo and call to action
  end: 55,
};

/** The length of the edit in grid seconds (the film is DURATION × PACE seconds). */
export const DURATION = T.end;
