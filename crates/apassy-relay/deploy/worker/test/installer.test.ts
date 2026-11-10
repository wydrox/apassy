import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
const execute = promisify(execFile);
const installer = fileURLToPath(new URL('../public/install.sh', import.meta.url));
function fixture(t: TestContext, os = 'Darwin', arch = 'arm64', version = 'apassy-team 0.5.8') {
  const dir = mkdtempSync(join(tmpdir(), 'relay-installer-'));
  t.after(() => rmSync(dir, {recursive:true,force:true}));
  const bin = join(dir,'bin'); mkdirSync(bin);
  const dl = join(dir,'dl'); mkdirSync(dl);
  const target = join(dir,'target'); mkdirSync(target);
  const marker = join(dir,'downloads');
  writeFileSync(join(bin,'uname'), `#!/bin/sh\ncase "$1" in -s) echo '${os}';; -m) echo '${arch}';; esac\n`,{mode:0o755});
  writeFileSync(join(bin,'curl'), `#!/bin/sh\nprintf '%s\\n' "$*" >> '${marker}'\nfor arg do url=$arg; done\ncat "\${url#file://}"\n`,{mode:0o755});
  const blob = `#!/bin/sh\nprintf '%s\\n' '${version}'\n`;
  const filename = 'apassy-team-darwin-arm64';
  writeFileSync(join(dl,filename),blob);
  writeFileSync(join(dl,'SHA256SUMS'),`${createHash('sha256').update(blob).digest('hex')}  ${filename}\n`);
  const installed = join(target,'apassy-team'); writeFileSync(installed,'old-binary');
  return {dir, installed, marker, run: (extraEnv: Record<string, string> = {}) => execute('/bin/sh',[installer], {env:{...process.env,
    HOME:dir, PATH:`${bin}:${process.env.PATH}`, APASSY_INSTALL_AS_ROOT:'1', APASSY_INSTALL_DIR:target, APASSY_RELAY_URL:`file://${dir}`, APASSY_COMPONENT:'node', ...extraEnv}})};
}
for (const [os,arch] of [['Darwin','x86_64']]) {
  test(`unsupported ${os}/${arch} fails before any download`,async t => {
    const f = fixture(t,os,arch);
    await assert.rejects(f.run(), (e: Error & {stderr?:string}) => /Supported platforms: macOS arm64, Linux x86_64, and Linux aarch64/.test(e.stderr ?? ''));
    assert.equal(existsSync(f.marker),false);
    assert.equal(readFileSync(f.installed,'utf8'),'old-binary');
  });
}

// The Linux node (plan S2-S3, L3): apassy-<version>-linux-<arch>.tar.gz with `apassy` and
// the `apassy-team` shim. `extra` adds an entry next to the package directory.
async function nodeFixture(t: TestContext, arch: string, nodeArch: string, extra = false) {
  const f = fixture(t, 'Linux', arch);
  const top = `apassy-0.5.8-linux-${nodeArch}`;
  const tree = join(f.dir, 'tree');
  mkdirSync(join(tree, top), {recursive:true});
  writeFileSync(join(tree, top, 'apassy'), `#!/bin/sh\nif [ "$1" = team ]; then shift; echo "apassy-team 0.5.8 $*"; else echo 'apassy 0.5.8'; fi\n`, {mode:0o755});
  writeFileSync(join(tree, top, 'apassy-team'), readFileSync(fileURLToPath(new URL('../../../../../packaging/linux/apassy-team', import.meta.url))), {mode:0o755});
  const names = [top];
  if (extra) { writeFileSync(join(tree, 'outside'), 'x'); names.push('outside'); }
  const tarball = join(f.dir, 'dl', `${top}.tar.gz`);
  await execute('tar', ['-czf', tarball, '-C', tree, ...names], {env:{...process.env, COPYFILE_DISABLE:'1'}});
  const blob = readFileSync(tarball);
  writeFileSync(join(f.dir,'dl','SHA256SUMS'), `${createHash('sha256').update(blob).digest('hex')}  ${top}.tar.gz\n`);
  return f;
}
for (const [arch, nodeArch] of [['x86_64','x86_64'],['aarch64','aarch64']]) {
  test(`Linux ${arch} installs the node and the apassy-team shim from the tarball`, async t => {
    const f = await nodeFixture(t, arch, nodeArch);
    const output = await f.run();
    assert.match(output.stdout, /apassy 0\.5\.8/);
    assert.match(output.stderr, /Next: apassy up/);
    const target = join(f.dir, 'target');
    const team = await execute(join(target, 'apassy-team'), ['me']);
    assert.equal(team.stdout, 'apassy-team 0.5.8 me\n');
    assert.match(readFileSync(join(target, 'apassy'), 'utf8'), /apassy 0\.5\.8/);
  });
}
test('a Linux tarball with an entry outside its directory is refused', async t => {
  const f = await nodeFixture(t, 'x86_64', 'x86_64', true);
  await assert.rejects(f.run(), /entries outside/);
  assert.equal(readFileSync(f.installed, 'utf8'), 'old-binary');
  assert.equal(existsSync(join(f.dir, 'target', 'apassy')), false);
});
test('staged version validation preserves the installed binary on failure',async t => {
  const f = fixture(t,'Darwin','arm64','wrong-program');
  await assert.rejects(f.run(), /staged executable/);
  assert.equal(readFileSync(f.installed,'utf8'),'old-binary');
});
test('successful update bounds downloads and explains per-team host restart',async t => {
  const f = fixture(t);
  const agents = join(f.dir,'Library','LaunchAgents'); mkdirSync(agents,{recursive:true});
  writeFileSync(join(agents,'com.wydrox.apassy.team-host.t_abcdefgh23.plist'),'synthetic');
  const output = await f.run();
  assert.match(output.stdout,/Installed/);
  assert.match(output.stdout,/apassy-team 0.5.8/);
  assert.match(output.stderr,/--team t_abcdefgh23 host install/);
  assert.match(output.stderr,/host status/);
  assert.match(readFileSync(f.marker,'utf8'),/--connect-timeout 10 --max-time 120/);
});

test('a checksum mismatch never executes or replaces the downloaded binary', async t => {
  const f = fixture(t);
  const executed = join(f.dir, 'executed');
  writeFileSync(join(f.dir, 'dl', 'apassy-team-darwin-arm64'), `#!/bin/sh\ntouch '${executed}'\necho apassy-team 0.5.8\n`);
  await assert.rejects(f.run(), /SHA-256 check failed/);
  assert.equal(existsSync(executed), false);
  assert.equal(readFileSync(f.installed, 'utf8'), 'old-binary');
});

// Vault mode is explicit and system-wide. Fixtures replace the packaged installer
// with a marker script; these tests never write to the host's /usr tree.
async function vaultFixture(t: TestContext, arch = 'x86_64', extra = false) {
  const f = fixture(t, 'Linux', arch);
  writeFileSync(join(f.dir, 'bin', 'id'), '#!/bin/sh\necho 0\n', {mode:0o755});
  const nodeArch = arch === 'arm64' ? 'aarch64' : arch;
  const top = `apassy-vault-0.5.8-linux-${nodeArch}`;
  const tree = join(f.dir, 'vault-tree');
  mkdirSync(join(tree, top, 'usr', 'bin'), {recursive:true});
  writeFileSync(join(tree, top, 'usr', 'bin', 'apassy'), "#!/bin/sh\necho 'apassy 0.5.8'\n", {mode:0o755});
  const executed = join(f.dir, 'vault-installed');
  writeFileSync(join(tree, top, 'install-vault.sh'), `#!/bin/sh\ntouch '${executed}'\n`, {mode:0o755});
  const names = [top];
  if (extra) { writeFileSync(join(tree, 'outside'), 'x'); names.push('outside'); }
  const tarball = join(f.dir, 'dl', `${top}.tar.gz`);
  await execute('tar', ['-czf', tarball, '-C', tree, ...names], {env:{...process.env, COPYFILE_DISABLE:'1'}});
  const blob = readFileSync(tarball);
  writeFileSync(join(f.dir, 'dl', 'SHA256SUMS'), `${createHash('sha256').update(blob).digest('hex')}  ${top}.tar.gz\n`);
  return {...f, executed, tarball, runVault: (extraEnv: Record<string, string> = {}) =>
    f.run({APASSY_COMPONENT:'vault', APASSY_INSTALL_DIR:'', ...extraEnv})};
}
for (const arch of ['x86_64', 'arm64']) {
  test(`vault mode explicitly selects the Linux ${arch} archive`, async t => {
    const f = await vaultFixture(t, arch);
    const output = await f.runVault();
    assert.match(output.stdout, /apassy 0\.5\.8/);
    assert.equal(existsSync(f.executed), true);
    assert.equal(readFileSync(f.installed, 'utf8'), 'old-binary');
  });
}
test('vault mode refuses a custom prefix before downloading', async t => {
  const f = await vaultFixture(t);
  await assert.rejects(f.runVault({APASSY_INSTALL_DIR:join(f.dir, 'unsafe')}), /fixed \/usr paths/);
  assert.equal(existsSync(f.marker), false);
  assert.equal(existsSync(f.executed), false);
});
test('vault mode refuses missing explicit root authorization before downloading', async t => {
  const f = await vaultFixture(t);
  await assert.rejects(f.runVault({APASSY_INSTALL_AS_ROOT:'0'}), /Do not run as root/);
  assert.equal(existsSync(f.marker), false);
  assert.equal(existsSync(f.executed), false);
});
test('vault checksum mismatch never executes its installer', async t => {
  const f = await vaultFixture(t);
  writeFileSync(f.tarball, 'tampered');
  await assert.rejects(f.runVault(), /SHA-256 check failed/);
  assert.equal(existsSync(f.executed), false);
});
test('vault tarball with an outside entry never executes its installer', async t => {
  const f = await vaultFixture(t, 'x86_64', true);
  await assert.rejects(f.runVault(), /entries outside/);
  assert.equal(existsSync(f.executed), false);
});
test('unknown installer component is refused before downloading', async t => {
  const f = fixture(t);
  await assert.rejects(f.run({APASSY_COMPONENT:'unexpected'}), /must be node or vault/);
  assert.equal(existsSync(f.marker), false);
});

test('vault archive links are refused before its installer executes', async t => {
  const f = await vaultFixture(t);
  const tree = join(f.dir, 'vault-tree');
  const top = 'apassy-vault-0.5.8-linux-x86_64';
  symlinkSync('/tmp', join(tree, top, 'unsafe-link'));
  await execute('tar', ['-czf', f.tarball, '-C', tree, top], {env:{...process.env, COPYFILE_DISABLE:'1'}});
  const blob = readFileSync(f.tarball);
  writeFileSync(join(f.dir, 'dl', 'SHA256SUMS'), `${createHash('sha256').update(blob).digest('hex')}  ${top}.tar.gz\n`);
  await assert.rejects(f.runVault(), /link or a special file/);
  assert.equal(existsSync(f.executed), false);
});
