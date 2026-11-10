import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { lstatSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Workers static assets serve files up to 25 MiB. */
export const MAX_ASSET_BYTES = 25 * 1024 * 1024;

export function verifyAssets(directory, version, commit) {
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error('Expected a full source commit.');
  if (!lstatSync(directory).isDirectory() || lstatSync(directory).isSymbolicLink()) throw new Error('Invalid download directory.');
  const read = name => {
    const path = join(directory, name);
    if (!lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) throw new Error(`Invalid asset: ${name}`);
    return readFileSync(path);
  };
  const metadata = JSON.parse(read('release.json').toString());
  if (metadata.version !== version || metadata.commit !== commit) throw new Error('Downloads must match this release version and source commit.');
  const sums = read('SHA256SUMS').toString().trim().split('\n').sort();
  const expected = [];
  for (const platform of ['darwin-arm64', 'linux-x86_64']) {
    const name = `apassy-team-${platform}`;
    const asset = metadata.artifacts?.[platform];
    const bytes = read(name);
    const hash = createHash('sha256').update(bytes).digest('hex');
    if (asset?.filename !== name || asset.sha256 !== hash || asset.size !== bytes.length || bytes.length === 0) throw new Error(`Unverified download: ${name}`);
    // CI also runs --version and inspects the architecture of both actual binaries.
    const magic = platform === 'darwin-arm64' ? 'cffaedfe' : '7f454c46';
    if (bytes.subarray(0, 4).toString('hex') !== magic) throw new Error(`Wrong binary format: ${name}`);
    expected.push(`${hash}  ${name}`);
  }
  // The Linux node packages (plan S2-S3, L3): both tarballs (gzip) and both .debs (ar).
  const node = metadata.node;
  const names = [`apassy-${version}-linux-x86_64.tar.gz`, `apassy-${version}-linux-aarch64.tar.gz`,
    `apassy_${version}_amd64.deb`, `apassy_${version}_arm64.deb`];
  if (!node || typeof node !== 'object' || JSON.stringify(Object.keys(node).sort()) !== JSON.stringify([...names].sort())) {
    throw new Error('release.json must list exactly the four Linux node packages.');
  }
  for (const name of names) {
    const bytes = read(name);
    const hash = createHash('sha256').update(bytes).digest('hex');
    const asset = node[name];
    if (asset?.sha256 !== hash || asset.size !== bytes.length || bytes.length === 0) throw new Error(`Unverified download: ${name}`);
    const magic = name.endsWith('.deb') ? '213c617263683e0a' : '1f8b';
    if (bytes.subarray(0, magic.length / 2).toString('hex') !== magic) throw new Error(`Wrong package format: ${name}`);
    expected.push(`${hash}  ${name}`);
  }
  // The Linux vault packages (ADR 0045, unit L6): both tarballs and both .debs, each at
  // most 25 MiB, the largest file that Workers static assets serve.
  const vault = metadata.vault;
  const vaultNames = [`apassy-vault-${version}-linux-x86_64.tar.gz`, `apassy-vault-${version}-linux-aarch64.tar.gz`,
    `apassy-vault_${version}_amd64.deb`, `apassy-vault_${version}_arm64.deb`];
  if (!vault || typeof vault !== 'object' || JSON.stringify(Object.keys(vault).sort()) !== JSON.stringify([...vaultNames].sort())) {
    throw new Error('release.json must list exactly the four Linux vault packages.');
  }
  for (const name of vaultNames) {
    const bytes = read(name);
    const hash = createHash('sha256').update(bytes).digest('hex');
    const asset = vault[name];
    if (asset?.sha256 !== hash || asset.size !== bytes.length || bytes.length === 0) throw new Error(`Unverified download: ${name}`);
    if (bytes.length > MAX_ASSET_BYTES) throw new Error(`Too large for /dl/ (25 MiB): ${name}`);
    const magic = name.endsWith('.deb') ? '213c617263683e0a' : '1f8b';
    if (bytes.subarray(0, magic.length / 2).toString('hex') !== magic) throw new Error(`Wrong package format: ${name}`);
    expected.push(`${hash}  ${name}`);
  }
  if (JSON.stringify(sums) !== JSON.stringify(expected.sort())) throw new Error('SHA256SUMS must verify exactly the ten downloads.');
  return metadata;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const worker = resolve(dirname(fileURLToPath(import.meta.url)), '..');
    const version = JSON.parse(readFileSync(join(worker, 'package.json'))).version;
    const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: worker, encoding: 'utf8' }).trim();
    const rootVersion = readFileSync(join(worker, '../../Cargo.toml'), 'utf8').match(/^version = "([^"]+)"/m)?.[1];
    if (rootVersion !== version) throw new Error('Worker and relay release versions differ.');
    verifyAssets(join(worker, 'public/dl'), version, commit);
    console.log(`Verified both CLI downloads, the four Linux node packages and the four Linux vault packages for ${version} at ${commit}.`);
  } catch (error) {
    console.error(`Worker asset preflight failed: ${error.message}`);
    process.exitCode = 1;
  }
}
