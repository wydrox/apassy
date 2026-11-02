import pathlib,json,hashlib,struct,os,datetime
base=pathlib.Path.home()/'Library/Application Support/net.imput.helium';ident='bbnpgnjnfjlbgggmpnhejpmfjhmmhiih';out=pathlib.Path('/Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/ext-suggest');repo=pathlib.Path('/Users/rafalw/.t3/worktrees/apassy/t3-1a34448f')
pref=json.loads((base/'Default/Secure Preferences').read_bytes());e=pref['extensions']['settings'][ident];ext=base/'Default/Extensions'/e['path'];manifest=json.loads((ext/'manifest.json').read_bytes());hostpath=base/'NativeMessagingHosts/com.wydrox.apassy.json';host=json.loads(hostpath.read_bytes());binary=pathlib.Path(host['path']);
result={'readAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'id':ident,'installedPath':str(ext),'version':manifest['version'],'disableReasons':e.get('disable_reasons'),'activePermissions':e.get('active_permissions'),'persistentScriptPatterns':e.get('persistent_script_url_patterns'),'hostManifestPath':str(hostpath),'hostManifest':host,'hostBinaryExists':binary.exists(),'hostBinaryExecutable':os.access(binary,os.X_OK),'hostBinarySHA256':hashlib.sha256(binary.read_bytes()).hexdigest(),'hashes':{f:{'owner':hashlib.sha256((ext/f).read_bytes()).hexdigest(),'main':hashlib.sha256((repo/'extension'/f).read_bytes()).hexdigest()}for f in ['background.js','fill.js','popup.js','popup.html','popup.css','login-worker.js','login-target.js','login-suggestions.js','passkey-bridge.js','passkey-page.js']}}
def varint(b,p):
 v=0;s=0
 while True:
  x=b[p];p+=1;v|=(x&127)<<s
  if x<128:return v,p
  s+=7
rows=[]
for path in (base/'Default/Extension Scripts').glob('*.log'):
 b=path.read_bytes();fragment=b'';p=0
 while p+7<=len(b):
  if p%32768>32761:p=(p//32768+1)*32768;continue
  crc,length,kind=struct.unpack_from('<IHB',b,p);p+=7
  if length==0 and kind==0:continue
  part=b[p:p+length];p+=length
  if kind==1:record=part
  elif kind==2:fragment=part;continue
  elif kind==3:fragment+=part;continue
  elif kind==4:record=fragment+part;fragment=b''
  else:continue
  if len(record)<12:continue
  seq,count=struct.unpack_from('<QI',record);q=12
  try:
   for i in range(count):
    tag=record[q];q+=1;n,q=varint(record,q);key=record[q:q+n];q+=n;value=None
    if tag==1:n,q=varint(record,q);value=record[q:q+n];q+=n
    if ident.encode() in key and b'dynamic_scripts' in key:rows.append({'sequence':seq+i,'kind':tag,'key':key.decode(),'value':json.loads(value) if value else None,'source':str(path)})
  except (IndexError,ValueError):pass
result['latestDynamicScriptWrite']=max(rows,key=lambda r:r['sequence']) if rows else None
result['dynamicScriptHistoryRecords']=len(rows)
(out/'owner-install.json').write_text(json.dumps(result,indent=2));print(json.dumps({'version':result['version'],'latest':result['latestDynamicScriptWrite'],'records':len(rows)},indent=2))
