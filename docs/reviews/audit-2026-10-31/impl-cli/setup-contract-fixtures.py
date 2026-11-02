import json, os, pathlib, socket, subprocess, tempfile, threading
BIN = pathlib.Path('/Users/rafalw/Dev/.target-cli1/debug/apassy')
TOKEN = 'apassy_agt_synthetic_contract_only'
count = 0
with tempfile.TemporaryDirectory(prefix='apassy-setup-', dir='/tmp') as scratch:
    base = pathlib.Path(scratch)
    for host in ['claude', 'codex']:
        home = base / host
        home.mkdir()
        fake = home / 'bin'
        fake.mkdir()
        claude = fake / 'claude'
        claude.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
if os.environ.get('SYNTHETIC_HOST_FAIL'): sys.exit(1)
p = pathlib.Path(os.environ['HOME']) / '.claude.json'
p.write_text(json.dumps({'mcpServers': {'apassy': {'type':'stdio','command':sys.argv[-1],'args':[],'env':{}}}}))
''')
        claude.chmod(0o700)
        env = dict(os.environ, HOME=str(home), CODEX_HOME=str(home / '.codex'), APASSY_OWNER_SOCKET=str(home / 'absent.sock'), PATH=str(fake)+':'+os.environ['PATH'])
        env.pop('CLAUDE_CONFIG_DIR', None)
        env.pop('APASSY_SESSION', None)
        def call(*args, token='', code=0, extra=None):
            global count
            result = subprocess.run([str(BIN),'--json','setup',host,*args], env=env | (extra or {}), input=token, text=True, capture_output=True)
            assert result.returncode == code, (host,args,result.returncode,result.stderr)
            report = json.loads(result.stdout)
            assert report['ok'] == (code == 0), report
            assert TOKEN not in result.stdout + result.stderr
            count += 1
            return report
        call()
        assert not (home / '.config').exists()
        hooks = home / ('.claude/settings.json' if host == 'claude' else '.codex/hooks.json')
        hooks.parent.mkdir(exist_ok=True)
        hooks.write_text('{"disableAllHooks":true}')
        call('--write','--token-stdin', token=TOKEN, code=1)
        assert not (home / '.config').exists()
        hooks.write_text('{}')
        call('--write', code=3)
        assert not (home / '.config').exists()
        report = call('--write','--token-stdin', token=TOKEN)
        wrapper = home / '.config/apassy' / f'apassy-mcp-{host}.sh'
        original = wrapper.read_bytes()
        call('--write')
        assert wrapper.read_bytes() == original
        if host == 'codex':
            config = home / '.codex/config.toml'
            text = config.read_text()
            config.write_text(text.replace('= 660', '= 330'))
            call('--write')
            assert '= 660' in config.read_text()
            config.write_text(config.read_text().replace('= 660','= 900'))
            call('--write')
            assert '= 900' in config.read_text()
        else:
            settings = json.loads(hooks.read_text())
            settings['env']['MCP_TOOL_TIMEOUT'] = '330000'
            hooks.write_text(json.dumps(settings))
            call('--write')
            assert json.loads(hooks.read_text())['env']['MCP_TOOL_TIMEOUT'] == '660000'
            settings['env']['MCP_TOOL_TIMEOUT'] = '900000'
            hooks.write_text(json.dumps(settings))
            call('--write')
            assert json.loads(hooks.read_text())['env']['MCP_TOOL_TIMEOUT'] == '900000'
        wrapper.write_text('#!/bin/sh\necho user command\n')
        call('--write', code=1)
        assert 'echo user command' in wrapper.read_text()
    # Host failure after wrappers: JSON must disclose partial state and retry reuses them.
    home = base / 'partial'
    home.mkdir()
    env.update(HOME=str(home), CODEX_HOME=str(home / '.codex'))
    host = 'claude'
    result = call('--write','--token-stdin',token=TOKEN,code=1,extra={'SYNTHETIC_HOST_FAIL':'1'})
    assert result['data']['partial']
    call('--write')
print(f'{count} isolated CLI JSON/setup contract cases passed')
