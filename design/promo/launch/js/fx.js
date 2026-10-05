// The background: one flat color, which cuts (or blends) between keys. The film is light;
// the silence before the drop is black. Scenes register keys at build time.

import { lerp, prog, ease, global } from './engine.js';

const keys = [];

/** From grid time t the background is `color` ([r, g, b]), blended in over `blend`. */
export const bg = (t, color, blend = 0) => {
  keys.push({ t, color, blend });
  keys.sort((a, b) => a.t - b.t);
};

export const LIGHT = [245, 245, 247];
export const BLACK = [0, 0, 0];

function bgAt(t) {
  let c = LIGHT;
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i];
    if (t < k.t) break;
    const prev = i ? keys[i - 1].color : LIGHT;
    const p = k.blend ? ease.inOutSine(prog(t, k.t, k.t + k.blend)) : 1;
    c = prev.map((v, j) => lerp(v, k.color[j], p));
  }
  return c;
}

export function install(stage) {
  global((t) => {
    const [r, g, b] = bgAt(t);
    stage.style.background = `rgb(${r | 0},${g | 0},${b | 0})`;
  });
}
