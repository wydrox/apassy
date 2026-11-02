import json, os, pathlib, socket, subprocess, tempfile, threading
with tempfile.TemporaryDirectory(prefix='setup-refusal-',dir='/tmp') as scratch:
    home=pathlib.Path(scratch)
    listener=socket.socket(socket.AF_UNIX)
    path=home/'owner.sock'
    listener.bind(str(path)); listener.listen(1)
    def refuse():
        connection,_=listener.accept()
        with connection:
            request=json.loads(connection.makefile('rb').readline())
            assert request['command']['cmd']=='agent_connect'
            connection.sendall(json.dumps({'ok':False,'code':'refused','message':'Synthetic owner refusal.','data':{'type':'none'}}).encode()+b'\n')
    thread=threading.Thread(target=refuse); thread.start()
    env=dict(os.environ,HOME=str(home),CODEX_HOME=str(home/'.codex'),APASSY_OWNER_SOCKET=str(path))
    env.pop('APASSY_SESSION',None)
    result=subprocess.run(['/Users/rafalw/Dev/.target-cli1/debug/apassy','--json','setup','codex','--write'],env=env,text=True,capture_output=True)
    thread.join(timeout=5); listener.close()
    assert not thread.is_alive()
    assert result.returncode==1, result.stderr
    response=json.loads(result.stdout)
    assert response['code']=='refused' and not response['data']['partial'] and not response['data']['changes_unknown'], response
    assert not (home/'.config').exists()
print('Synthetic owner refusal: one JSON document, exit 1, no configuration writes')
