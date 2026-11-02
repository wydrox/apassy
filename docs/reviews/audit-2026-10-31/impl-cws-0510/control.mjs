import fs from 'node:fs';
import readline from 'node:readline';
const out=new URL('.',import.meta.url).pathname;
const info=await(await fetch('http://127.0.0.1:9223/json/version')).json();
const ws=new WebSocket(info.webSocketDebuggerUrl);await new Promise(r=>ws.onopen=r);
let n=0;const pending=new Map();ws.onmessage=e=>{const v=JSON.parse(e.data),p=pending.get(v.id);if(p){pending.delete(v.id);v.error?p.reject(Error(JSON.stringify(v.error))):p.resolve(v.result)}};
const cmd=(method,params={},sessionId)=>new Promise((resolve,reject)=>{const id=++n;pending.set(id,{resolve,reject});ws.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}))});
const t=(await cmd('Target.createTarget',{url:'https://chrome.google.com/webstore/devconsole'})).targetId;
const s=(await cmd('Target.attachToTarget',{targetId:t,flatten:true})).sessionId;
await cmd('Page.enable',{},s);
const ev=async expression=>{const r=await cmd('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},s);if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value};
const snap=async name=>{const r=await cmd('Page.captureScreenshot',{format:'png',captureBeyondViewport:true},s);fs.writeFileSync(out+name,Buffer.from(r.data,'base64'));return name};
console.log('READY');
for await(const line of readline.createInterface({input:process.stdin})){try{console.log(JSON.stringify(await eval(line)))}catch(e){console.log('ERROR '+e.message)}}
await cmd('Target.closeTarget',{targetId:t});ws.close();
