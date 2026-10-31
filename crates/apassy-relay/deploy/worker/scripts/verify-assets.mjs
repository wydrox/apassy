import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { lstatSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

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
  if (JSON.stringify(sums) !== JSON.stringify(expected.sort())) throw new Error('SHA256SUMS must verify exactly both downloads.');
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
    console.log(`Verified both CLI downloads for ${version} at ${commit}.`);
  } catch (error) {
    console.error(`Worker asset preflight failed: ${error.message}`);
    process.exitCode = 1;
  }
}
