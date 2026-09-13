import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';
const core=await readFile(new URL('./core.js',import.meta.url),'utf8');
const background=await readFile(new URL('./background.js',import.meta.url),'utf8');
const event=()=>({listeners:[],addListener(fn){this.listeners.push(fn);}});
async function harness({navigate=false,chrome=false,pairReason="done",nativeError,paired=false}={}) {
  let stored=paired?{paired:true}:{},polls=0,signatures=0,connects=0,saving=false;
  const fills=[],commands=[],registrations=[],injections=[];
  const tab={id:1,windowId:1,active:true,url:'https://example.com/login'};
  const runtime={id:'factorseal-test',getURL:p=>`extension://factorseal/${p}`,onMessage:event(),onInstalled:event(),connectNative(){
    connects++;
    const port={onMessage:event(),onDisconnect:event(),disconnect(){for(const fn of this.onDisconnect.listeners)fn();},postMessage(request){
      (async()=>{
        if(nativeError){runtime.lastError={message:nativeError};port.disconnect();delete runtime.lastError;return;}
        let response;
        if(request.type==='hello') response={type:'hello',version:1,session:'a'.repeat(64)};
        else {
          const {key,payload,signature}=request.message;
          const publicKey=await webcrypto.subtle.importKey('raw',Buffer.from(key,'hex'),'Ed25519',false,['verify']);
          assert.equal(await webcrypto.subtle.verify('Ed25519',publicKey,Buffer.from(signature,'hex'),new TextEncoder().encode(payload)),true);signatures++;
          const command=JSON.parse(payload);commands.push(command);
          if(command.action.type==='pair')response={type:'finished',reason:pairReason};
          else if(command.action.type==='revoke')response={type:'finished',reason:'done'};
          else if(command.action.type==='detect'){response={type:'state',state:'awaiting_unseal'};}
          else if(command.action.type==='save'){
            saving=true;response={type:'state',state:'awaiting_approval'};
            if(navigate){tab.url='https://example.com/account';for(const fn of api.tabs.onUpdated.listeners)fn(tab.id,{url:tab.url,status:'loading'});}
          }
          else if(command.action.type==='poll') {
            polls++;
            if(saving)response={type:'finished',reason:'done'};
            else if(polls===1)response={type:'state',state:'matching'};
            else if(polls===2)response={type:'state',state:'awaiting_approval'};
            else if(polls===3){if(navigate)tab.url='https://evil.test/';response={type:'context',nonce:'c'.repeat(64)};}
            else response={type:'fill',username:Buffer.from('alice').toString('base64'),password:Buffer.from('secret').toString('base64')};
          } else if(command.action.type==='confirm')response={type:'state',state:'releasing'};
          else response={type:'finished',reason:'cancelled'};
        }
        for(const fn of port.onMessage.listeners)fn(response);
      })().catch(e=>{throw e;});
    }};
    return port;
  }};
  const api={runtime,storage:{local:{get:async key=>({[key]:stored[key]}),set:async values=>Object.assign(stored,values),setAccessLevel:async()=>{}}},
    permissions:{contains:async()=>true,onAdded:event(),onRemoved:event()},
    scripting:{getRegisteredContentScripts:async()=>registrations,registerContentScripts:async scripts=>registrations.push(...scripts),executeScript:async options=>injections.push(options),unregisterContentScripts:async()=>{}},
    tabs:{query:async()=>[tab],get:async()=>tab,sendMessage:async(_tab,m)=>{if(m.type==='check')return {valid:true,document:m.document};fills.push(m);return {filled:true};},onRemoved:event(),onActivated:event(),onUpdated:event()},
    windows:{get:async()=>({focused:true}),onFocusChanged:event()}};
  const navigator=chrome?{userAgentData:{brands:[{brand:'Chromium'}]}}:{userAgent:'Firefox/129'};
  const context={navigator,crypto:webcrypto,TextEncoder,TextDecoder,URL,atob,btoa,setTimeout:(fn,ms)=>setTimeout(fn,ms===350?1:ms),clearTimeout,console};
  context[chrome?'chrome':'browser']=api;
  vm.runInNewContext(core,context);vm.runInNewContext(background,context);
  const message=(m,sender)=>new Promise(resolve=>runtime.onMessage.listeners[0](m,sender,resolve));
  const sender={id:runtime.id,frameId:0,tab,url:tab.url};
  return {message,sender,fills,commands,registrations,injections,setNativeError(value){nativeError=value;},get connects(){return connects;},get signatures(){return signatures;},get stored(){return stored;}};
}
async function until(condition){for(let i=0;i<300;i++){if(condition())return;await new Promise(r=>setTimeout(r,10));}throw new Error('timed out');}
test('submitted save survives navigation and never persists credentials in extension storage',async()=>{
  const h=await harness({paired:true,navigate:true});
  assert.equal((await h.message({type:'save',document:'doc',username:'alice',password:'秘密'},h.sender)).accepted,true);
  await until(()=>h.commands.some(c=>c.action.type==='poll'));
  const save=h.commands.find(c=>c.action.type==='save').action;
  assert.equal(save.origin,'https://example.com');
  assert.equal(Buffer.from(save.password,'base64').toString(),'秘密');
  assert.equal(h.commands.some(c=>c.action.type==='cancel'),false);
  assert.equal(h.fills.length,0);
  assert.deepEqual(Object.keys(h.stored).sort(),['paired','pairing']);
});
test('unpaired and cross-origin senders cannot offer saves',async()=>{
  for(const paired of [false,true]){
    const h=await harness({paired});
    const sender=paired?{...h.sender,url:'https://evil.test'}:h.sender;
    assert.equal((await h.message({type:'save',document:'doc',username:'alice',password:'secret'},sender)).accepted,false);
    assert.equal(h.connects,0);
  }
});
test('popup recovers after Desktop starts without submitting another pairing request',async()=>{
  const h=await harness({nativeError:'Specified native messaging host not found.'});
  const sender={url:'extension://factorseal/popup.html'};
  await h.message({type:'pair'},sender);
  await until(()=>h.connects===1);
  h.setNativeError(undefined);
  let state;
  for(let i=0;i<100;i++){
    state=await h.message({type:'status'},sender);
    if(state.status==='idle')break;
    await new Promise(r=>setTimeout(r,5));
  }
  assert.equal(state.status,'idle');
  assert.equal(state.pending,null);
  assert.equal(state.paired,false);
  assert.equal(h.connects,2);
  assert.equal(h.commands.length,0);
});
for(const nativeError of ['Specified native messaging host not found.','No such native application dev.factorseal.browser','Native host has exited.'])test(`native connection guidance: ${nativeError}`,async()=>{
  const h=await harness({nativeError});
  const sender={url:'extension://factorseal/popup.html'};
  await h.message({type:'pair'},sender);
  let state;
  for(let i=0;i<100;i++){
    state=await h.message({type:'status'},sender);
    if(!state.pending)break;
    await new Promise(r=>setTimeout(r,5));
  }
  assert.equal(state.status,nativeError==='Native host has exited.'?'native_disconnected':'desktop_missing');
  assert.equal(state.paired,false);
  assert.equal(h.commands.length,0);
});
for(const chrome of [false,true])test(`${chrome?'Chromium':'Firefox'} adapter signs requests and fills only after context confirmation`,async()=>{
  const h=await harness({chrome});assert.equal((await h.message({type:'detected',document:'doc'},h.sender)).accepted,true);
  await until(()=>h.fills.length===1);
  assert.equal(h.fills[0].password,'secret');assert.equal(h.fills[0].document,'doc');
  assert.equal(h.commands[0].browser,chrome?'chromium':'firefox');
  assert.ok(h.commands.find(c=>c.action.type==='confirm'));
  assert.equal(new Set(h.commands.map(c=>c.sequence)).size,h.commands.length);
  assert.ok(h.signatures>=6);assert.deepEqual(Object.keys(h.stored),['pairing']);
  assert.ok(!JSON.stringify(h.stored).includes('secret'));
});
test('navigation while desktop approval is pending cancels instead of releasing',async()=>{
  const h=await harness({navigate:true});await h.message({type:'detected',document:'doc'},h.sender);
  await until(()=>h.commands.some(c=>c.action.type==='cancel'));
  assert.equal(h.fills.length,0);assert.ok(!h.commands.some(c=>c.action.type==='confirm'));
});
test('untrusted frames and forged extension control messages cannot reach the host',async()=>{
  const h=await harness();
  for(const [message,sender] of [
    [{type:'detected',document:'doc'},{...h.sender,frameId:2}],
    [{type:'pair'},h.sender],
    [{type:'detected',document:'doc'},{...h.sender,id:'another-extension'}],
    [{type:'detected',document:'doc'},{...h.sender,url:'https://evil.test'}],
  ]) assert.notEqual((await h.message(message,sender)).accepted,true);
  assert.equal(h.connects,0);
});

const popupSender={url:'extension://factorseal/popup.html'};
test('pairing UI state persists only after approval and clears after revocation',async()=>{
  const h=await harness();
  assert.equal((await h.message({type:'status'},popupSender)).paired,false);
  assert.equal(h.registrations.length,0);
  await h.message({type:'pair'},popupSender);
  await until(()=>h.stored.paired===true);
  await until(()=>h.injections.length===1);
  assert.equal(h.registrations[0].id,'factorseal-login');
  assert.equal(h.injections[0].target.tabId,1);
  assert.equal((await h.message({type:'status'},popupSender)).paired,true);
  await until(()=>h.commands.length>0);
  await h.message({type:'revoke'},popupSender);
  await until(()=>h.stored.paired===false);
  assert.equal((await h.message({type:'status'},popupSender)).paired,false);
});
test('denied pairing does not unlock the paired UI',async()=>{
  const h=await harness({pairReason:'denied'});
  await h.message({type:'pair'},popupSender);
  await until(()=>h.commands.some(c=>c.action.type==='pair'));
  assert.equal((await h.message({type:'status'},popupSender)).paired,false);
  assert.equal(h.registrations.length,0);
  assert.equal(h.injections.length,0);
});
