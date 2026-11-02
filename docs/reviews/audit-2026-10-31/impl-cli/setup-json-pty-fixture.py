import errno, fcntl, json, os, pathlib, pty, socket, subprocess, tempfile, termios
with tempfile.TemporaryDirectory(prefix='setup-json-pty-',dir='/tmp') as scratch:
    home=pathlib.Path(scratch); path=home/'owner.sock'
    listener=socket.socket(socket.AF_UNIX); listener.bind(str(path)); listener.listen(1); listener.settimeout(15)
    master,slave=pty.openpty()
    def session():
        os.setsid(); fcntl.ioctl(slave,termios.TIOCSCTTY,0)
    env=dict(os.environ,HOME=str(home),CODEX_HOME=str(home/'.codex'),APASSY_OWNER_SOCKET=str(path))
    for key in ['APASSY_SESSION','CLAUDE_CONFIG_DIR','APASSY_DEBUG_DATA_DIR']: env.pop(key,None)
    child=subprocess.Popen(['/Users/rafalw/Dev/.target-cli1/debug/apassy','--json','setup','codex','--write'],stdin=slave,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,preexec_fn=session)
    os.close(slave)
    connection,_=listener.accept()
    with connection:
        request=json.loads(connection.makefile('rb').readline())
        assert request['command']['cmd']=='agent_connect'
        agent={'id':1,'name':'Synthetic Codex','created_at':1,'revoked':False,'token_expires_at':9999999999,'token_expired':False,'sees_all':True}
        response={'ok':True,'code':'ok','message':'Synthetic connection approved.','data':{'type':'token','agent':agent,'token':'apassy_agt_synthetic_pty_only'}}
        connection.sendall(json.dumps(response).encode()+b'\n')
    out,err=child.communicate(timeout=15); listener.close()
    assert child.returncode==0,err.decode()
    report=json.loads(out)
    assert report['ok'] and 'agent_connected' in report['data']['stages']
    assert b'Connected Synthetic Codex' in err,err.decode()
    fcntl.fcntl(master,fcntl.F_SETFL,os.O_NONBLOCK)
    try: tty=os.read(master,65536)
    except OSError as error:
        assert error.errno in [errno.EIO,errno.EAGAIN]; tty=b''
    os.close(master)
    assert not tty,tty
    assert b'apassy_agt_synthetic_pty_only' not in out+err+tty
print('Controlling-TTY JSON connection: one stdout document, progress only on stderr, no token output')
