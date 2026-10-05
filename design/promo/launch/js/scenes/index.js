// The launch film: the scenes in order. Each module registers its scene and sound cues.
export { DURATION, PACE } from '../timeline.js';
export const NAME = 'launch';
export const out = (format) => (format === 'tall' ? 'apassy-launch-9x16.mp4' : 'apassy-launch.mp4');

import './hook.js';
import './reveal.js';
import './vault.js';
import './placeholder.js';
import './rules.js';
import './bouncer.js';
import './approval.js';
import './learning.js';
import './proof.js';
import './outro.js';
