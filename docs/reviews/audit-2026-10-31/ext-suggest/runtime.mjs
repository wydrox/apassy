import fs from 'node:fs';
import {spawn} from 'node:child_process';
const state=JSON.parse(fs.readFileSync('/tmp/apassy-ext-audit-state.json'));
const {startServer}=await import(state.repo+'/extension-tests/support/pages.mjs');
const server=await startServer();state.fixturePort=server.port;
const log=fs.openSync(state.root+'/helium.log','a');
const proc=spawn('/Applications/Helium.app/Contents/MacOS/Helium',[
`--user-data-dir=${state.profile}`,'--remote-debugging-port=9341',`--load-extension=${state.repo}/extension`,`--disable-extensions-except=${state.repo}/extension`,'--enable-unsafe-extension-debugging','--no-first-run','--no-default-browser-check','--headless=new','--use-mock-keychain','--password-store=basic','--window-size=1280,900','about:blank'],{env:{...process.env,HOME:state.home,APASSY_BROWSER_SOCKET:state.root+'/never-owner.sock'},stdio:['ignore',log,log]});
state.pid=proc.pid;state.runtimePid=process.pid;fs.writeFileSync('/tmp/apassy-ext-audit-state.json',JSON.stringify(state));console.log(JSON.stringify(state));
const stop=()=>{proc.kill('SIGTERM');server.close();};process.on('SIGTERM',stop);process.on('SIGINT',stop);proc.on('exit',(code)=>{server.close();console.log('Helium exit',code);process.exit(0);});
