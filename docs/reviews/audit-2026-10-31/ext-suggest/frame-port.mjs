import fs from 'node:fs';
import {browser,worker,page,targets,delay,connect} from './cdp.mjs';
const S=JSON.parse(fs.readFileSync('/tmp/apassy-ext-audit-state.json')),b=await browser(),w=await worker();
const rows=[];const req=()=>fs.readFileSync(S.root+'/real-requests.jsonl','utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
const handle=m=>w.eval(`self.apassyHandle(${JSON.stringify(m)})`);
async function shot(p,n){const s=await p.send('Page.captureScreenshot',{format:'png'});fs.writeFileSync(S.out+'/'+n+'.png',Buffer.from(s.data,'base64'));}
async function tab(p){const u=await p.eval('location.href');return(await w.eval('chrome.tabs.query({})')).find(t=>t.url===u)}
async function snap(p){const t=await tab(p);return w.eval(`chrome.scripting.executeScript({target:{tabId:${t.id},allFrames:true},func:()=>({url:location.href,script:!!self.apassyLoginTarget,enabled:self.apassyLoginSuggestionsEnabled===true,active:document.activeElement?.id,eligible:!!self.apassyLoginTarget?.eligible(document.activeElement),capture:self.apassyLoginTarget?.capture(),menu:[...document.querySelectorAll('[data-apassy-login-suggestions]')].map(e=>e.dataset.state)})})`)}
async function text(p){const doc=await p.send('DOM.getDocument',{depth:-1,pierce:true});const out=[];function walk(n,on=false){on=on||(n.attributes||[]).includes('data-apassy-login-suggestions');if(on&&n.nodeType===3&&!n.nodeValue.startsWith(':host'))out.push(n.nodeValue);for(const c of [...(n.children||[]),...(n.shadowRoots||[]),...(n.contentDocument?[n.contentDocument]:[])])walk(c,on)}walk(doc.root);return out;}
async function capture(name,p,extra={}){const x={name,...extra,snapshot:await snap(p),menu:await text(p),badge:await w.eval('chrome.action.getBadgeText({})')};rows.push(x);await shot(p,name);fs.writeFileSync(S.out+'/frame-port.json',JSON.stringify(rows,null,2));console.log(JSON.stringify(x));return x;}
const p=await page('about:blank');for(const t of await targets())if(t.type==='page'&&t.id!==p.id)await b.send('Target.closeTarget',{targetId:t.id});await p.send('Network.enable');
const {startServer}=await import(S.repo+'/extension-tests/support/pages.mjs');const secondary=await startServer();
try{await p.send('Page.navigate',{url:`http://localhost:${S.fixturePort}/blank`});await delay(250);await p.send('Page.bringToFront');await p.eval(`let f=document.createElement('iframe');f.src='http://localhost:${secondary.port}/typed';document.body.append(f)`);await delay(500);
const t=await tab(p);await w.eval(`chrome.scripting.executeScript({target:{tabId:${t.id},allFrames:true},func:()=>document.querySelector('#username')?.focus()})`);await delay(400);await capture('cross-origin-port-frame',p,{secondaryPort:secondary.port});
}finally{secondary.close();p.close();w.close();b.close();}
