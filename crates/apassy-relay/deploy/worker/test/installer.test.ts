import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
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
  return {dir, installed, marker, run: () => execute('/bin/sh',[installer], {env:{...process.env,
    HOME:dir, PATH:`${bin}:${process.env.PATH}`, APASSY_INSTALL_AS_ROOT:'1', APASSY_INSTALL_DIR:target, APASSY_RELAY_URL:`file://${dir}`}})};
}
for (const [os,arch] of [['Darwin','x86_64'],['Linux','aarch64']]) {
  test(`unsupported ${os}/${arch} fails before any download`,async t => {
    const f = fixture(t,os,arch);
    await assert.rejects(f.run(), (e: Error & {stderr?:string}) => /Supported platforms: macOS arm64 and Linux x86_64/.test(e.stderr ?? ''));
    assert.equal(existsSync(f.marker),false);
    assert.equal(readFileSync(f.installed,'utf8'),'old-binary');
  });
}
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
