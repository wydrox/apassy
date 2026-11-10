import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MAX_ASSET_BYTES, verifyAssets } from '../scripts/verify-assets.mjs';

test('deployment requires the ten downloads, exact hashes, version and provenance', () => {
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
    const node: Record<string, { sha256: string; size: number }> = {};
    for (const filename of ['apassy-0.5.7-linux-x86_64.tar.gz', 'apassy-0.5.7-linux-aarch64.tar.gz',
      'apassy_0.5.7_amd64.deb', 'apassy_0.5.7_arm64.deb']) {
      const bytes = Buffer.from(filename.endsWith('.deb') ? '213c617263683e0a01' : '1f8b0801', 'hex');
      const sha256 = createHash('sha256').update(bytes).digest('hex');
      writeFileSync(join(dir, filename), bytes);
      node[filename] = { sha256, size: bytes.length };
      sums.push(`${sha256}  ${filename}`);
    }
    const vault: Record<string, { sha256: string; size: number }> = {};
    for (const filename of ['apassy-vault-0.5.7-linux-x86_64.tar.gz', 'apassy-vault-0.5.7-linux-aarch64.tar.gz',
      'apassy-vault_0.5.7_amd64.deb', 'apassy-vault_0.5.7_arm64.deb']) {
      const bytes = Buffer.from(filename.endsWith('.deb') ? '213c617263683e0a02' : '1f8b0802', 'hex');
      const sha256 = createHash('sha256').update(bytes).digest('hex');
      writeFileSync(join(dir, filename), bytes);
      vault[filename] = { sha256, size: bytes.length };
      sums.push(`${sha256}  ${filename}`);
    }
    // Without the node packages in release.json, the staging is refused.
    writeFileSync(join(dir, 'release.json'), JSON.stringify({ version: '0.5.7', commit, artifacts, vault }));
    writeFileSync(join(dir, 'SHA256SUMS'), sums.join('\n') + '\n');
    assert.throws(() => verifyAssets(dir, '0.5.7', commit), /four Linux node packages/);
    // Without the vault packages too.
    writeFileSync(join(dir, 'release.json'), JSON.stringify({ version: '0.5.7', commit, artifacts, node }));
    assert.throws(() => verifyAssets(dir, '0.5.7', commit), /four Linux vault packages/);
    writeFileSync(join(dir, 'release.json'), JSON.stringify({ version: '0.5.7', commit, artifacts, node, vault }));
    verifyAssets(dir, '0.5.7', commit);
    // SHA256SUMS without a vault line is refused.
    writeFileSync(join(dir, 'SHA256SUMS'), sums.slice(0, -1).join('\n') + '\n');
    assert.throws(() => verifyAssets(dir, '0.5.7', commit), /ten downloads/);
    writeFileSync(join(dir, 'SHA256SUMS'), sums.join('\n') + '\n');
    // A vault package over the 25 MiB that /dl/ can serve is refused.
    const big = Buffer.alloc(MAX_ASSET_BYTES + 1);
    Buffer.from('213c617263683e0a', 'hex').copy(big);
    const bigName = 'apassy-vault_0.5.7_arm64.deb';
    const bigSum = createHash('sha256').update(big).digest('hex');
    writeFileSync(join(dir, bigName), big);
    writeFileSync(join(dir, 'release.json'), JSON.stringify({ version: '0.5.7', commit, artifacts, node,
      vault: { ...vault, [bigName]: { sha256: bigSum, size: big.length } } }));
    writeFileSync(join(dir, 'SHA256SUMS'), sums.map(line => line.endsWith(bigName) ? `${bigSum}  ${bigName}` : line).join('\n') + '\n');
    assert.throws(() => verifyAssets(dir, '0.5.7', commit), /Too large/);
    writeFileSync(join(dir, bigName), Buffer.from('213c617263683e0a02', 'hex'));
    writeFileSync(join(dir, 'release.json'), JSON.stringify({ version: '0.5.7', commit, artifacts, node, vault }));
    writeFileSync(join(dir, 'SHA256SUMS'), sums.join('\n') + '\n');
    verifyAssets(dir, '0.5.7', commit);
    writeFileSync(join(dir, 'apassy_0.5.7_arm64.deb'), Buffer.from('1f8b0801', 'hex'));
    assert.throws(() => verifyAssets(dir, '0.5.7', commit), /Unverified download/);
    writeFileSync(join(dir, 'apassy_0.5.7_arm64.deb'), Buffer.from('213c617263683e0a01', 'hex'));
    verifyAssets(dir, '0.5.7', commit);
    assert.throws(() => verifyAssets(dir, '0.5.8', commit));
    assert.throws(() => verifyAssets(dir, '0.5.7', 'b'.repeat(40)));
    writeFileSync(join(dir, 'apassy-team-linux-x86_64'), 'modified');
    assert.throws(() => verifyAssets(dir, '0.5.7', commit));
    rmSync(join(dir, 'apassy-team-darwin-arm64'));
    assert.throws(() => verifyAssets(dir, '0.5.7', commit));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
