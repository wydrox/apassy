import os,json,pathlib
h=pathlib.Path.home(); d=h/'.config/apassy'
for host in ['claude','codex']:
 for name in ['mcp','hook']:
  p=d/f'apassy-{name}-{host}.sh';p.write_text('#!/bin/sh\nexit 0\n');p.chmod(0o700)
 command=str(d/f'apassy-mcp-{host}.sh')
 hook={'hooks':{'UserPromptSubmit':[{'hooks':[{'type':'command','command':"'"+str(d/f'apassy-hook-{host}.sh')+"'"}]}]}}
 if host=='claude':
  (h/'.claude/.claude.json').write_text(json.dumps({'mcpServers':{'apassy':{'command':command}}}))
  (h/'.claude/settings.json').write_text(json.dumps(hook))
 else:
  (h/'.codex/config.toml').write_text('[mcp_servers.apassy]\ncommand = '+json.dumps(command)+'\n')
  (h/'.codex/hooks.json').write_text(json.dumps(hook))
 (d/f'connection-{host}.json').write_text(json.dumps({'agent_id':'1','version':'0.5.8'}))
 if os.environ['REVIEW37_STATE']=='needs-repair':
  (d/f'apassy-hook-{host}.sh').unlink()
