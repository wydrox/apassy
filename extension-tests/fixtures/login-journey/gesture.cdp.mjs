// Real-event regression in an isolated Helium profile over CDP (port 9351).
// Start Helium with only this checkout's unpacked extension. No native app/host
// is contacted: the worker's native transport and popup messages are intercepted
// before the popup loads. This proves event handling, not signed-native acceptance.
import assert from "node:assert/strict";
const endpoint = "http://127.0.0.1:9351";
async function connect(url) {
  const ws=new WebSocket(url); await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
  let id=0; const pending=new Map();
  ws.onmessage=(e)=>{const m=JSON.parse(e.data);if(m.id){const p=pending.get(m.id);pending.delete(m.id);if(m.error)p.reject(Error(JSON.stringify(m.error)));else p.resolve(m.result);}};
  return {call(method,params={}) {return new Promise((resolve,reject)=>{const n=++id;pending.set(n,{resolve,reject});ws.send(JSON.stringify({id:n,method,params}));});},close(){ws.close();}};
}
const targets=await (await fetch(`${endpoint}/json/list`)).json();
const worker=targets.find(t=>t.type==="service_worker" && t.url.includes("bbnpgnjnfjlbgggmpnhejpmfjhmmhiih"));
const bg=worker ? await connect(worker.webSocketDebuggerUrl) : null;
const tab=await (await fetch(`${endpoint}/json/new?about:blank`,{method:"PUT"})).json();
let page;
try {
  if(bg) await bg.call("Runtime.evaluate",{expression:'ask = async () => { throw new Error("Synthetic gesture check: native transport disabled"); };'});
  page=await connect(tab.webSocketDebuggerUrl);
  await page.call("Page.enable");
  await page.call("Page.addScriptToEvaluateOnNewDocument",{source:`
    globalThis.__gestureMessages=[];
    chrome.runtime.sendMessage=async message=>{
      __gestureMessages.push(message);
      if(message.type==="state")return {ok:true,state:"list",host:"example.test",tabId:1,url:"https://example.test",logins:[{item:7,title:"Synthetic login",username:"synthetic@example.test",hasTotp:true}]};
      return {ok:true,on:false,message:"Synthetic response"};
    };
  `});
  await page.call("Page.navigate",{url:"chrome-extension://bbnpgnjnfjlbgggmpnhejpmfjhmmhiih/popup.html"});
  async function evaluate(expression) {
    const r=await page.call("Runtime.evaluate",{expression,returnByValue:true,awaitPromise:true});
    if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value;
  }
  const ready=await evaluate(`new Promise((resolve,reject)=>{let tries=0;const timer=setInterval(()=>{if(document.querySelector("button.login")){clearInterval(timer);resolve(true);}else if(++tries>100){clearInterval(timer);reject(Error("popup did not load"));}},20);})`);
  assert.equal(ready,true);
  await evaluate(`document.querySelector("button.login").click(); document.querySelector("button.code").dispatchEvent(new MouseEvent("click",{bubbles:true}));`);
  assert.equal(await evaluate(`__gestureMessages.filter(m=>["fill","fill_code"].includes(m.type)).length`),0,"synthetic popup events must be refused");
  const box=await evaluate(`(()=>{const r=document.querySelector("button.login").getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};})()`);
  await page.call("Input.dispatchMouseEvent",{type:"mousePressed",button:"left",clickCount:1,...box});
  await page.call("Input.dispatchMouseEvent",{type:"mouseReleased",button:"left",clickCount:1,...box});
  const messages=await evaluate(`new Promise(resolve=>setTimeout(()=>resolve(__gestureMessages.filter(m=>m.type==="fill")),50))`);
  assert.equal(messages.length,1);assert.equal(messages[0].trustedGesture,true);
  console.log("PASS: synthetic popup password/code events refused; real CDP click carries trusted gesture; native transport disabled.");
} finally {
  await fetch(`${endpoint}/json/close/${tab.id}`);
  page?.close();bg?.close();
}
