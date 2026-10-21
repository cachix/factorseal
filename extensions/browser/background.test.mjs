import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';
const core=await readFile(new URL('./core.js',import.meta.url),'utf8');
const background=await readFile(new URL('./background.js',import.meta.url),'utf8');
const event=()=>({listeners:[],addListener(fn){this.listeners.push(fn);}});
async function harness({navigate=false,chrome=false,pairReason="done",nativeError,paired=false,forgotten=0,focused=true,owned=true,untouched=true,picture='data:image/jpeg;base64,/9j/4AAQ'}={}) {
  let stored=paired?{paired:true}:{},polls=0,signatures=0,connects=0,saving=false,deadPort=false;
  const fills=[],commands=[],payloads=[],registrations=[],injections=[],notices=[];
  const tab={id:1,windowId:1,active:true,url:'https://example.com/login'};
  const runtime={id:'factorseal-test',getURL:p=>`extension://factorseal/${p}`,onMessage:event(),onInstalled:event(),connectNative(){
    connects++;
    // As in the browsers, onDisconnect reports only the host going away, not
    // the extension closing the port itself; a closed port throws on use.
    const port={onMessage:event(),onDisconnect:event(),closed:false,disconnect(){this.closed=true;},hostGone(){for(const fn of this.onDisconnect.listeners)fn();},postMessage(request){
      // Chrome throws this when the host is gone before onDisconnect fires.
      if(deadPort||this.closed){deadPort=false;throw new Error('Attempting to use a disconnected port object');}
      (async()=>{
        if(nativeError){runtime.lastError={message:nativeError};port.hostGone();delete runtime.lastError;return;}
        let response;
        if(request.type==='hello') response={type:'hello',version:1,session:'a'.repeat(64)};
        else {
          const {key,payload,signature}=request.message;
          const publicKey=await webcrypto.subtle.importKey('raw',Buffer.from(key,'hex'),'Ed25519',false,['verify']);
          assert.equal(await webcrypto.subtle.verify('Ed25519',publicKey,Buffer.from(signature,'hex'),new TextEncoder().encode(payload)),true);signatures++;
          const command=JSON.parse(payload);commands.push(command);payloads.push(payload.length);
          if(forgotten>0){forgotten--;response={type:'finished',reason:'unauthorized'};}
          else if(command.action.type==='pair')response={type:'finished',reason:pairReason};
          else if(command.action.type==='revoke')response={type:'finished',reason:'done'};
          else if(command.action.type==='detect'){response={type:'state',state:'awaiting_unseal'};}
          else if(['save','one_time'].includes(command.action.type)){
            saving=true;response={type:'state',state:command.action.type==='save'?'awaiting_approval':'reading'};
            if(navigate){tab.url='https://example.com/account';for(const fn of api.tabs.onUpdated.listeners)fn(tab.id,{url:tab.url,status:'loading'});}
          }
          else if(command.action.type==='image')response={type:'state',state:'reading'};
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
  const api={runtime,storage:{local:{get:async keys=>Object.fromEntries([keys].flat().map(key=>[key,stored[key]])),set:async values=>Object.assign(stored,values),setAccessLevel:async()=>{}}},
    permissions:{contains:async()=>true,onAdded:event(),onRemoved:event()},
    scripting:{getRegisteredContentScripts:async()=>registrations,registerContentScripts:async scripts=>registrations.push(...scripts),executeScript:async options=>injections.push(options),unregisterContentScripts:async()=>{}},
    tabs:{query:async()=>[tab],get:async id=>id===tab.id?tab:{...tab,id},captureVisibleTab:async()=>{if(picture instanceof Error)throw picture;return picture;},sendMessage:async(_tab,m)=>{if(m.type==='pressed')return {valid:owned && untouched};if(['check','owns'].includes(m.type))return {valid:owned,document:m.document};if(m.type==='find')return {document:tab.form===false?null:'doc'};if(m.type==='save-current')return {offered:true};if(['notice','close-notice','site-changed'].includes(m.type)){notices.push(m);return {};}fills.push(m);return {filled:true};},onRemoved:event(),onActivated:event(),onUpdated:event()},
    windows:{get:async()=>({focused}),onFocusChanged:event()}};
  let now=Date.now();
  const saveTimers=new Map();
  const clock=class extends Date {static now(){return now;}};
  const schedule=(fn,ms)=>{
    if(ms!==120000)return setTimeout(fn,ms===350?1:ms);
    const timer={};saveTimers.set(timer,{fn,until:clock.now()+ms});return timer;
  };
  const clear=timer=>{if(!saveTimers.delete(timer))clearTimeout(timer);};
  const navigator=chrome?{userAgentData:{brands:[{brand:'Chromium'}]}}:{userAgent:'Firefox/129'};
  const context={navigator,crypto:webcrypto,TextEncoder,TextDecoder,URL,atob,btoa,Date:clock,setTimeout:schedule,clearTimeout:clear,console};
  context[chrome?'chrome':'browser']=api;
  vm.runInNewContext(core,context);vm.runInNewContext(background,context);
  const message=(m,sender)=>new Promise(resolve=>runtime.onMessage.listeners[0](m,sender,resolve));
  const sender={id:runtime.id,frameId:0,tab,url:tab.url};
  const field={id:runtime.id,frameId:3,tab,url:'extension://factorseal/field.html?f1#doc'};
  const notice={id:runtime.id,frameId:4,tab,url:'extension://factorseal/notice.html?save#doc'};
  return {message,sender,field,notice,notices,tab,
    pendingCount:()=>vm.runInNewContext('pendingSaves.size',context),
    get saveTimerCount(){return saveTimers.size;},
    advance(ms){now+=ms;for(const [timer,{fn,until}] of saveTimers)if(until<=clock.now()){saveTimers.delete(timer);fn();}},
    closeTab(){for(const fn of api.tabs.onRemoved.listeners)fn(tab.id);},fills,commands,payloads,registrations,injections,setNativeError(value){nativeError=value;},killPort(){deadPort=true;},get connects(){return connects;},get signatures(){return signatures;},get stored(){return stored;}};
}
async function until(condition){for(let i=0;i<300;i++){if(condition())return;await new Promise(r=>setTimeout(r,10));}throw new Error('timed out');}
test('submitted save survives navigation and never persists credentials in extension storage',async()=>{
  const h=await harness({paired:true,navigate:true});
  assert.equal((await h.message({type:'save',document:'doc',username:'alice',password:'秘密'},h.sender)).accepted,true);
  assert.equal((await h.message({type:'notice-save',document:'doc',frame:'save'},h.notice)).accepted,true);
  await until(()=>h.commands.findLastIndex(c=>c.action.type==='poll')>h.commands.findIndex(c=>c.action.type==='save'));
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
  const h=await harness({chrome,paired:true});assert.equal((await h.message({type:'fill-field',document:'doc',frame:'f1'},h.field)).accepted,true);
  await until(()=>h.fills.length===1);
  assert.equal(h.fills[0].password,'secret');assert.equal(h.fills[0].document,'doc');
  assert.equal(h.commands[0].browser,chrome?'chromium':'firefox');
  assert.ok(h.commands.find(c=>c.action.type==='confirm'));
  assert.equal(new Set(h.commands.map(c=>c.sequence)).size,h.commands.length);
  assert.ok(h.signatures>=6);assert.deepEqual(Object.keys(h.stored).sort(),['paired','pairing']);
  assert.ok(!JSON.stringify(h.stored).includes('secret'));
  assert.equal(JSON.stringify(h.notices[0]),'{"type":"notice"}');
});
test('navigation while desktop approval is pending cancels instead of releasing',async()=>{
  const h=await harness({navigate:true,paired:true});await h.message({type:'fill-field',document:'doc',frame:'f1'},h.field);
  await until(()=>h.commands.some(c=>c.action.type==='cancel'));
  assert.equal(h.fills.length,0);assert.ok(!h.commands.some(c=>c.action.type==='confirm'));
});
test('untrusted frames and forged extension control messages cannot reach the host',async()=>{
  const h=await harness();
  for(const [message,sender] of [
    [{type:'field',document:'doc'},{...h.sender,frameId:2}],
    [{type:'pair'},h.sender],
    [{type:'fill-field',document:'doc',frame:'f1'},h.sender],
    [{type:'fill-field',document:'doc',frame:'f1'},{...h.field,id:'another-extension'}],
    [{type:'fill-field',document:'doc',frame:'f1'},{...h.field,url:'https://evil.test/field.html#doc'}],
    [{type:'notice-save',document:'doc',frame:'save'},{...h.notice,url:'extension://factorseal/popup.html#doc'}],
  ]) assert.notEqual((await h.message(message,sender)).accepted,true);
  assert.equal(h.connects,0);
});
test('a field button only fills the document whose own content script made it',async()=>{
  const h=await harness({paired:true,owned:false});
  assert.equal((await h.message({type:'fill-field',document:'doc',frame:'f1'},h.field)).accepted,false);
  assert.equal((await h.message({type:'notice-save',document:'doc',frame:'save'},h.notice)).accepted,false);
  assert.ok(!h.commands.some(c=>c.action.type==='detect'));
});
test('fields show the FactorSeal button only to a paired profile on a site that is not paused',async()=>{
  assert.equal((await (await harness()).message({type:'field',document:'doc'},(await harness()).sender)).show,false);
  const h=await harness({paired:true});
  assert.equal((await h.message({type:'field',document:'doc'},h.sender)).show,true);
  await h.message({type:'pause'},{url:'extension://factorseal/popup.html'});
  assert.equal((await h.message({type:'field',document:'doc'},h.sender)).show,false);
  assert.ok(h.notices.some(n=>n.type==='site-changed'));
  assert.equal((await h.message({type:'fill-field',document:'doc',frame:'f1'},h.field)).accepted,false);
  assert.equal((await h.message({type:'save',document:'doc',username:'alice',password:'secret'},h.sender)).accepted,false);
});
test('the popup still fills and saves a paused site when asked',async()=>{
  const popup={url:'extension://factorseal/popup.html'};
  const filling=await harness({paired:true});
  await filling.message({type:'pause'},popup);
  assert.equal((await filling.message({type:'fill'},popup)).found,true);
  await until(()=>filling.commands.some(c=>c.action.type==='detect'));
  const saving=await harness({paired:true});
  await saving.message({type:'pause'},popup);
  assert.equal((await saving.message({type:'save-page'},popup)).offered,true);
  assert.equal((await saving.message({type:'save',document:'doc',username:'alice',password:'secret'},saving.sender)).accepted,true);
  await until(()=>saving.commands.some(c=>c.action.type==='save'));
});
test('a sign-in asks on the page first, also on the next page of the same site, and Desktop sees the login only after Save',async()=>{
  const h=await harness({paired:true});
  assert.equal(JSON.stringify(await h.message({type:'save',document:'doc',username:'alice',password:'secret'},h.sender)),'{"accepted":true,"ask":true}');
  await new Promise(r=>setTimeout(r,20));
  assert.ok(!h.commands.some(c=>c.action.type==='save'));
  for(const [url,save] of [['https://news.test/',false],['https://app.example.com/home',true]]){
    h.tab.url=url;
    assert.equal((await h.message({type:'pending',document:'next'},{...h.sender,url})).save,save,url);
    assert.equal((await h.message({type:'notice-pending',document:'doc',frame:'save'},h.notice)).pending,save,url);
  }
  assert.equal((await h.message({type:'pending',document:'next'},{...h.sender,url:'https://other.test/'})).accepted,false);
  assert.equal((await h.message({type:'notice-save',document:'doc',frame:'save'},{...h.notice,tab:{...h.tab,id:2}})).accepted,false);
  assert.equal((await h.message({type:'notice-save',document:'doc',frame:'save'},h.notice)).accepted,true);
  await until(()=>h.commands.some(c=>c.action.type==='save'));
  assert.deepEqual([h.commands.find(c=>c.action.type==='save').action].map(({origin,username})=>`${origin} ${username}`),['https://example.com alice']);
  assert.equal(JSON.stringify(h.notices.at(-1)),'{"type":"notice"}');
  assert.equal((await h.message({type:'pending',document:'next'},{...h.sender,url:h.tab.url})).save,false);
});
test('a frame the page restyled cannot start a request',async()=>{
  const h=await harness({paired:true,untouched:false});
  assert.equal((await h.message({type:'fill-field',document:'doc',frame:'f1'},h.field)).accepted,false);
  await h.message({type:'save',document:'doc',username:'alice',password:'secret'},h.sender);
  assert.equal((await h.message({type:'notice-save',document:'doc',frame:'save'},h.notice)).accepted,false);
  assert.equal((await h.message({type:'notice-pending',document:'doc',frame:'save'},h.notice)).pending,true);
  assert.ok(!h.commands.some(c=>['detect','save'].includes(c.action.type)));
});
test('a request on the page keeps the save question for afterwards',async()=>{
  const h=await harness({paired:true});
  await h.message({type:'save',document:'doc',username:'alice',password:'secret'},h.sender);
  const status={...h.notice,url:'extension://factorseal/notice.html?status#doc'};
  assert.equal((await h.message({type:'notice-close',document:'doc',frame:'status'},status)).accepted,true);
  assert.equal(h.notices.at(-1).type,'close-notice');
  assert.equal((await h.message({type:'pending',document:'doc'},h.sender)).save,true);
});
test('the save question follows a sign-in only within the same site',async()=>{
  for(const [from,to,asked] of [
    ['https://www.example.com/login','https://accounts.example.com/',true],
    ['https://accounts.example.com/login','https://example.com/',true],
    ['https://example.co.uk/login','https://evil.co.uk/',false],
    ['https://alice.github.io/login','https://bob.github.io/',false],
    ['https://192.168.1.10/login','https://192.168.1.11/',false],
  ]){
    const h=await harness({paired:true});
    h.tab.url=from;
    await h.message({type:'save',document:'doc',username:'alice',password:'secret'},{...h.sender,url:from});
    h.tab.url=to;
    assert.equal((await h.message({type:'pending',document:'next'},{...h.sender,url:to})).save,asked,`${from} ${to}`);
  }
});
test('Not now forgets the login without asking Desktop',async()=>{
  const h=await harness({paired:true});
  await h.message({type:'save',document:'doc',username:'alice',password:'secret'},h.sender);
  assert.equal((await h.message({type:'notice-close',document:'doc',frame:'save'},h.notice)).accepted,true);
  assert.equal(h.notices.at(-1).type,'close-notice');
  assert.equal((await h.message({type:'pending',document:'doc'},h.sender)).save,false);
  assert.equal((await h.message({type:'notice-save',document:'doc',frame:'save'},h.notice)).accepted,false);
  assert.ok(!h.commands.some(c=>c.action.type==='save'));
});

const popupSender={url:'extension://factorseal/popup.html'};
test('the extension popup opened as a top-level tab can pair with Desktop',async()=>{
  const h=await harness();
  h.tab.url=popupSender.url;
  const sender={...h.sender,url:popupSender.url};
  assert.equal((await h.message({type:'status'},sender)).paired,false);
  assert.equal((await h.message({type:'pair'},sender)).status,'Approve pairing in Desktop');
  await until(()=>h.stored.paired===true);
  assert.equal((await h.message({type:'status'},sender)).paired,true);
});
test('web pages, foreign extensions, and embedded popup frames cannot request pairing',async()=>{
  for(const changed of [
    {url:'https://example.com/login'},
    {id:'other-extension'},
    {frameId:3},
    {tab:{id:1,url:'https://example.com/login'}},
  ]){
    const h=await harness();
    h.tab.url=popupSender.url;
    const sender={...h.sender,url:popupSender.url,...changed};
    assert.equal((await h.message({type:'pair'},sender)).accepted,false);
    assert.equal(h.connects,0);
  }
});
test('pairing UI state persists only after approval and clears after revocation',async()=>{
  const h=await harness();
  assert.equal((await h.message({type:'status'},popupSender)).paired,false);
  assert.equal(h.registrations.length,0);
  await h.message({type:'pair'},popupSender);
  await until(()=>h.stored.paired===true);
  await until(()=>h.injections.length===1);
  await until(()=>h.notices.some(n=>n.type==='site-changed'));
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

test('a native port that died before its disconnect was reported is reconnected',async()=>{
  const h=await harness();
  const sender={url:'extension://factorseal/popup.html'};
  await h.message({type:'pair'},sender);
  await until(()=>h.commands.length===1);
  h.killPort();
  await h.message({type:'pair'},sender);
  let state;
  for(let i=0;i<200;i++){
    state=await h.message({type:'status'},sender);
    if(state.status==='idle'&&h.connects===2)break;
    await new Promise(r=>setTimeout(r,5));
  }
  assert.notEqual(state.status,'Attempting to use a disconnected port object');
  assert.equal(h.connects,2);
  assert.equal(state.status,'idle');
});
test('after Desktop answers unauthorized, the next request connects again',async()=>{
  const h=await harness({pairReason:'unauthorized'});
  const sender={url:'extension://factorseal/popup.html'};
  // Each request is refused, sent once more on a new connection, refused again.
  await h.message({type:'pair'},sender);
  await until(()=>h.commands.length===2);
  await h.message({type:'pair'},sender);
  await until(()=>h.commands.length===4);
  assert.equal(h.connects,4);
});
test('a request Desktop refuses for a forgotten session connects again and is sent once more',async()=>{
  const h=await harness({forgotten:1});
  const sender={url:'extension://factorseal/popup.html'};
  await h.message({type:'pair'},sender);
  await until(()=>h.stored.paired===true);
  assert.equal(h.connects,2);
  assert.deepEqual(h.commands.map(c=>c.action.type),['pair','pair']);
  assert.notEqual(h.commands[0].session,undefined);
});
test('a request refused twice is not sent a third time',async()=>{
  const h=await harness({forgotten:5});
  const sender={url:'extension://factorseal/popup.html'};
  await h.message({type:'pair'},sender);
  await until(()=>h.commands.length===2);
  await new Promise(r=>setTimeout(r,50));
  assert.equal(h.commands.length,2);
  assert.notEqual(h.stored.paired,true);
});
test('Save login from this page is taken once while the popup keeps the focus',async()=>{
  const h=await harness({paired:true,focused:false});
  const popup={url:'extension://factorseal/popup.html'};
  const save=document=>h.message({type:'save',document,username:'alice',password:'secret'},h.sender);
  assert.equal((await save('before')).accepted,false);
  assert.equal((await h.message({type:'save-page'},popup)).offered,true);
  assert.equal((await save('page')).accepted,true);
  await until(()=>h.commands.some(c=>c.action.type==='save'));
  assert.equal((await save('again')).accepted,false);
});
test('a request status shows only on the tab and site it was about',async()=>{
  const h=await harness({paired:true});
  const popup={url:'extension://factorseal/popup.html'};
  assert.equal((await h.message({type:'save',document:'doc',username:'alice',password:'secret'},h.sender)).accepted,true);
  assert.equal((await h.message({type:'notice-save',document:'doc',frame:'save'},h.notice)).accepted,true);
  let state;
  await until(()=>h.commands.some(c=>c.action.type==='save'));
  for(let i=0;i<300;i++){state=await h.message({type:'status'},popup);if(state.status==='saved')break;await new Promise(r=>setTimeout(r,10));}
  assert.equal(state.status,'saved');
  h.tab.id=2;
  assert.equal((await h.message({type:'status'},popup)).status,'idle');
  h.tab.id=1;h.tab.url='https://other.test/login';
  assert.equal((await h.message({type:'status'},popup)).status,'idle');
  h.tab.url='https://example.com/login';
  assert.equal((await h.message({type:'status'},popup)).status,'saved');
});
test('Fill this page reports a page without a login form, on that page only',async()=>{
  const h=await harness({paired:true});
  const popup={url:'extension://factorseal/popup.html'};
  h.tab.form=false;
  assert.equal((await h.message({type:'fill'},popup)).found,false);
  assert.equal((await h.message({type:'status'},popup)).status,'No complete login form found on this page.');
  h.tab.id=2;
  assert.equal((await h.message({type:'status'},popup)).status,'idle');
});
test('Add one-time password asks Desktop about the current site and survives navigation',async()=>{
  const h=await harness({paired:true,navigate:true});
  const popup={url:'extension://factorseal/popup.html'};
  await h.message({type:'one-time'},popup);
  let state;
  for(let i=0;i<300;i++){state=await h.message({type:'status'},popup);if(state.status==='one_time_saved')break;await new Promise(r=>setTimeout(r,10));}
  assert.equal(state.status,'one_time_saved');
  assert.deepEqual(h.commands[0].action,{type:'one_time',origin:'https://example.com'});
  assert.equal(h.commands.some(c=>c.action.type==='cancel'),false);
  assert.equal(h.fills.length,0);
});
test('a page cannot ask for a one-time password',async()=>{
  const h=await harness({paired:true});
  assert.notEqual((await h.message({type:'one-time'},h.sender)).accepted,true);
  assert.equal(h.connects,0);
});
test('Add one-time password sends only the tab picture, in pieces Desktop frames can hold',async()=>{
  const bytes=Buffer.from(Array.from({length:100001},(_,i)=>i*7%256));
  const h=await harness({paired:true,picture:`data:image/jpeg;base64,${bytes.toString('base64')}`});
  const popup={url:'extension://factorseal/popup.html'};
  await h.message({type:'one-time'},popup);
  await until(()=>h.commands.some(c=>c.action.type==='poll'));
  const parts=h.commands.filter(c=>c.action.type==='image').map(c=>c.action);
  assert.ok(parts.length>1);
  assert.ok(parts.every(part=>part.size===bytes.length));
  assert.deepEqual(Buffer.concat(parts.map(part=>Buffer.from(part.data,'base64'))),bytes);
  assert.ok(h.payloads.every(length=>length<=63*1024));
  assert.deepEqual(h.commands.map(c=>c.action.type).slice(0,1),['one_time']);
  assert.equal(JSON.stringify(h.notices),'[{"type":"notice"}]');
});
test('a cancelled one-time password request stops sending the tab picture',async()=>{
  const picture=Buffer.alloc(2000000,7).toString('base64');
  const h=await harness({paired:true,picture:`data:image/jpeg;base64,${picture}`});
  const popup={url:'extension://factorseal/popup.html'};
  const images=()=>h.commands.filter(c=>c.action.type==='image').length;
  await h.message({type:'one-time'},popup);
  await until(()=>images()>0);
  await h.message({type:'cancel'},popup);
  const sent=images();
  await new Promise(r=>setTimeout(r,100));
  assert.ok(images()<=sent+1 && images()<Math.ceil(picture.length/43688));
});
test('a tab that cannot be captured says so and never reaches Desktop',async()=>{
  const h=await harness({paired:true,picture:new Error('capture refused')});
  const popup={url:'extension://factorseal/popup.html'};
  assert.equal((await h.message({type:'one-time'},popup)).status,'capture_failed');
  assert.equal((await h.message({type:'status'},popup)).status,'capture_failed');
  assert.ok(!h.commands.some(c=>c.action.type==='one_time'));
});

for(const action of ['pause','unpair'])test(`an existing save question is disabled after ${action}`,async()=>{
  const h=await harness({paired:true});
  await h.message({type:'save',document:'doc',username:'alice',password:'secret'},h.sender);
  assert.equal((await h.message({type:'notice-pending',document:'doc',frame:'save'},h.notice)).pending,true);
  if(action==='pause')await h.message({type:'pause'},popupSender);
  else h.stored.paired=false;
  assert.equal((await h.message({type:'notice-pending',document:'doc',frame:'save'},h.notice)).pending,false);
  assert.equal((await h.message({type:'notice-save',document:'doc',frame:'save'},h.notice)).accepted,false);
  assert.ok(!h.commands.some(c=>c.action.type==='save'));
});
test('pending credentials expire without any messages after navigation to an HTTP page',async()=>{
  const h=await harness({paired:true});
  await h.message({type:'save',document:'doc',username:'alice',password:'secret'},h.sender);
  h.tab.url='http://example.com/';
  h.advance(119999);
  assert.equal(h.pendingCount(),1);
  h.advance(1);
  assert.equal(h.pendingCount(),0);
  assert.equal(h.saveTimerCount,0);
  assert.ok(!h.commands.some(c=>c.action.type==='save'));
});
test('a replacement save gets its own full lifetime',async()=>{
  const h=await harness({paired:true});
  const save=password=>h.message({type:'save',document:'doc',username:'alice',password},h.sender);
  await save('old');
  h.advance(60000);
  await save('new');
  assert.equal(h.saveTimerCount,1);
  h.advance(60000);
  assert.equal(h.pendingCount(),1);
  h.advance(60000);
  assert.equal(h.pendingCount(),0);
});
for(const action of ['dismiss','save','close tab'])test(`pending cleanup is cancelled on ${action}`,async()=>{
  const h=await harness({paired:true});
  await h.message({type:'save',document:'doc',username:'alice',password:'secret'},h.sender);
  assert.equal(h.saveTimerCount,1);
  if(action==='close tab')h.closeTab();
  else await h.message({type:action==='save'?'notice-save':'notice-close',document:'doc',frame:'save'},h.notice);
  assert.equal(h.pendingCount(),0);
  assert.equal(h.saveTimerCount,0);
});
