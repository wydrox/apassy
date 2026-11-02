import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyAssets } from '../scripts/verify-assets.mjs';

test('deployment requires both downloads, exact hashes, version and provenance', () => {
  const dir = mkdtempSync(join(tmpdir(), 'relay-assets-'));
  const commit = 'a'.repeat(40);
  try {
    assert.throws(() => verifyAssets(dir, '0.5.7', commit)); // fresh checkout
    const artifacts: Record<string, { filename: string; sha256: string; size: number }> = {};
    const sums = [];
    for (const platform of ['darwin-arm64', 'linux-x86_64']) {
      const filename = `apassy-team-${platform}`;
      const bytes = Buffer.from(platform === 'darwin-arm64' ? 'cffaedfe01020304' : '7f454c4601020304', 'hex');
      const sha256 = createHash('sha256').update(bytes).digest('hex');
      writeFileSync(join(dir, filename), bytes);
      artifacts[platform] = { filename, sha256, size: bytes.length };
      sums.push(`${sha256}  ${filename}`);
    }
    writeFileSync(join(dir, 'release.json'), JSON.stringify({ version: '0.5.7', commit, artifacts }));
    writeFileSync(join(dir, 'SHA256SUMS'), sums.join('\n') + '\n');
    verifyAssets(dir, '0.5.7', commit);
    assert.throws(() => verifyAssets(dir, '0.5.8', commit));
    assert.throws(() => verifyAssets(dir, '0.5.7', 'b'.repeat(40)));
    writeFileSync(join(dir, 'apassy-team-linux-x86_64'), 'modified');
    assert.throws(() => verifyAssets(dir, '0.5.7', commit));
    rmSync(join(dir, 'apassy-team-darwin-arm64'));
    assert.throws(() => verifyAssets(dir, '0.5.7', commit));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
