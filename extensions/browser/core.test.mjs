import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';
await import('./core.js');
const {origin,validateResponse,decode}=globalThis.FactorSealCore;
test('identifies supported browser labels without claiming an unknown client is Chrome',()=>{
  const kind=globalThis.FactorSealCore.browserKind;
  assert.equal(kind({},true),'firefox');
  assert.equal(kind({userAgentData:{brands:[{brand:'Chromium'},{brand:'Google Chrome'}]}}),'chrome');
  assert.equal(kind({userAgentData:{brands:[{brand:'Chromium'},{brand:'Microsoft Edge'}]}}),'edge');
  assert.equal(kind({userAgent:'Chromium/137.0'}),'chromium');
  assert.equal(kind({}),undefined);
});
test('origin boundaries include scheme, subdomain, credentials, and port',()=>{
  assert.equal(origin('https://EXAMPLE.com:443/login?q=x'),'https://example.com');
  assert.notEqual(origin('https://example.com:444'),origin('https://example.com'));
  assert.notEqual(origin('https://evil.example.com'),origin('https://example.com'));
  for(const url of ['http://example.com','https://u:p@example.com','data:text/html,hi'])assert.throws(()=>origin(url));
});
test('strict responses and UTF-8 field decoding',()=>{
  assert.equal(decode(Buffer.from('秘密').toString('base64')),'秘密');
  assert.throws(()=>validateResponse({type:'fill',username:'a',password:'b',export:'all'}));
  assert.throws(()=>validateResponse({type:'hello',version:2,session:'a'.repeat(64)}));
  assert.throws(()=>validateResponse({type:'context',nonce:'short'}));
});
const script=await readFile(new URL('./content.js',import.meta.url),'utf8');
function page({hidden=false,crossOrigin=false,newPassword=false,confirmation=false,show=true,pending=false,ask=true}={}) {
  let listener,observer,overlay,scans=0;
  const events={},messages=[],frames=[];
  class Input {
    constructor(type){this.type=type;this.disabled=false;this.readOnly=false;this.autocomplete='';this._value='';}
    get value(){return this._value;} set value(v){this._value=v;}
    getClientRects(){return this.hidden?[]:[{}];}
    getBoundingClientRect(){const top=this.top??(this.type==='password'?50:10);return {left:10,top,right:210,bottom:top+30,width:200,height:30};}
    dispatchEvent(){this.onInput?.();}
  }
  const username=new Input('text'),password=new Input('password');
  const confirm=confirmation?new Input('password'):null;
  if(confirm){confirm.top=90;confirm.autocomplete='new-password';}
  password.hidden=hidden;password.autocomplete=newPassword?'new-password':'';
  const owner={action:crossOrigin?'https://evil.test/post':'https://example.com/post',querySelectorAll:()=>[username,password,...(confirm?[confirm]:[])]};
  password.form=owner;
  const node=()=>({style:{setProperty(name,value,priority){if(priority==='important')this[name.replace(/-(\w)/g,(_,c)=>c.toUpperCase())]=value;}},children:[],append(...children){this.children.push(...children);},remove(){this.removed=true;},attachShadow(options){this.shadow={options,...node()};return this.shadow;},
    getBoundingClientRect(){const width=parseFloat(this.style.width)||0,height=parseFloat(this.style.height)||0,left=this.style.left?parseFloat(this.style.left):1000-16-width,top=parseFloat(this.style.top)||0;return {left,top,width,height,right:left+width,bottom:top+height};}});
  const inside=(host,x,y)=>{const r=host.getBoundingClientRect();return x>=r.left && x<=r.right && y>=r.top && y<=r.bottom;};
  const doc={visibilityState:'visible',documentElement:{append(host){frames.push(host);}},createElement:node,querySelectorAll:()=>{scans++;return [password,...(confirm?[confirm]:[])];},addEventListener:(name,fn)=>{events[name]=fn;},elementsFromPoint:(x,y)=>[...(overlay?[overlay]:[]),...frames.filter(host=>!host.removed && host.style.pointerEvents!=='none' && (host.covers?.(y)??inside(host,x,y))).reverse(),y>85?confirm:y>45?password:username]};
  const window={addEventListener:()=>{}};window.top=window;
  const replies={field:{show},pending:{save:pending},save:{accepted:true,ask}};
  const context={crypto:webcrypto,URL,Event,TextEncoder,HTMLInputElement:Input,document:doc,innerWidth:1000,innerHeight:800,location:{protocol:'https:',origin:'https://example.com',href:'https://example.com/login'},window,
    getComputedStyle:element=>({visibility:'visible',display:element.style?.display==='none'?'none':'block',opacity:'1',filter:'none',clipPath:'none',pointerEvents:element.style?.pointerEvents||'auto',...element.computed}),setTimeout:fn=>{queueMicrotask(fn);},requestAnimationFrame:fn=>{queueMicrotask(fn);},addEventListener:()=>{},MutationObserver:class{constructor(fn){observer=fn;}observe(){}},
    browser:{runtime:{id:'test',getURL:path=>`extension://factorseal/${path}`,sendMessage:async message=>{messages.push(message);return replies[message.type]??{accepted:true};},onMessage:{addListener:f=>{listener=f;}}}}};
  vm.runInNewContext(script,context);
  const message=payload=>{let result;listener(payload,{id:'test'},r=>result=r);return result;};
  const token=()=>messages.find(m=>m.document)?.document;
  const views=()=>frames.filter(host=>!host.removed).map(host=>host.shadow.children[0].src);
  return {username,password,confirm,owner,context,message,messages,frames,views,token,doc,events,mutate:records=>observer(records),cover:element=>{overlay=element;},get scans(){return scans;},edit:()=>events.input({isTrusted:true}),submit:(trusted=true)=>events.submit({isTrusted:trusted,target:owner})};
}
const settle=()=>new Promise(resolve=>setImmediate(resolve));
for(const registration of [false,true])test(`offers submitted ${registration?'registration':'login'} credentials once`,async()=>{
  const p=page({newPassword:registration,confirmation:registration});
  p.username.value='alice';p.password.value='secret';if(p.confirm)p.confirm.value='secret';
  await settle();
  assert.equal(p.messages.filter(m=>m.type==='save').length,0);
  p.submit();p.submit();
  const saves=p.messages.filter(m=>m.type==='save');
  assert.equal(saves.length,1);
  assert.equal(saves[0].username,'alice');assert.equal(saves[0].password,'secret');
});
test('save ignores forged submits, hidden fields, cross-origin actions, and mismatched confirmation',()=>{
  for(const options of [{},{hidden:true},{crossOrigin:true},{newPassword:true,confirmation:true}]){
    const p=page(options);p.username.value='alice';p.password.value='secret';
    if(p.confirm)p.confirm.value='different';
    p.submit(Object.keys(options).length>0);
    assert.equal(p.messages.filter(m=>m.type==='save').length,0);
  }
});
test('explicit save and corrected submissions use the current fields',()=>{
  const p=page({newPassword:true});p.username.value='alice';p.password.value='first';
  assert.equal(p.message({type:'save-current'}).offered,true);
  p.password.value='corrected';p.edit();p.submit();
  const saves=p.messages.filter(m=>m.type==='save');
  assert.equal(saves.length,2);assert.equal(saves[1].password,'corrected');
});
test('finding the page form reports its document only when it has a login form',async()=>{
  const p=page();await settle();
  assert.equal(p.message({type:'find'}).document,p.token());
  for(const options of [{hidden:true},{crossOrigin:true},{newPassword:true}])assert.equal(page(options).message({type:'find'}).document,null);
});
test('the login fields get a FactorSeal button in a closed frame the page cannot reach',async()=>{
  const p=page();await settle();
  const [first,second]=p.views().map(view=>new URL(view));
  assert.ok([first,second].every(view=>view.href===`extension://factorseal/field.html${view.search}#${p.token()}` && view.search.length>1));
  assert.notEqual(first.search,second.search);
  assert.ok(p.frames.every(host=>host.shadow.options.mode==='closed' && host.style.display==='block'));
  assert.deepEqual([p.frames[0].style.left,p.frames[0].style.top],['182px','14px']);
  assert.equal(p.messages.filter(m=>m.type!=='pending').map(m=>m.type).join(),'field');
});
test('hidden, cross-origin and signup forms, paused sites and unpaired profiles get no button',async()=>{
  for(const options of [{hidden:true},{crossOrigin:true},{newPassword:true},{show:false}]){const p=page(options);await settle();assert.deepEqual(p.views(),[]);}
});
test('a site change asks again whether to show buttons',async()=>{
  const p=page({show:false});await settle();
  p.context.browser.runtime.sendMessage=async message=>{p.messages.push(message);return {show:true};};
  p.message({type:'site-changed'});await settle();await settle();
  assert.equal(p.views().length,2);
});
test('the save question shows when Desktop should ask, and again on the next page while pending',async()=>{
  const p=page();await settle();
  p.username.value='alice';p.password.value='secret';p.submit();await settle();
  assert.deepEqual(p.views().filter(view=>view.includes('notice')),[`extension://factorseal/notice.html?save#${p.token()}`]);
  assert.equal(p.frames.at(-1).style.pointerEvents,'auto');
  p.message({type:'notice'});
  assert.deepEqual(p.views().filter(view=>view.includes('notice')),[`extension://factorseal/notice.html?status#${p.token()}`]);
  assert.equal(p.frames.at(-1).style.pointerEvents,'none');
  p.message({type:'close-notice'});await settle();
  assert.deepEqual(p.views().filter(view=>view.includes('notice')),[]);
  const next=page({pending:true});await settle();
  assert.equal(next.views().filter(view=>view.includes('notice.html?save')).length,1);
  next.message({type:'notice'});
  next.message({type:'close-notice'});await settle();
  assert.equal(next.views().filter(view=>view.includes('notice.html?save')).length,1);
  const explicit=page({ask:false});await settle();
  explicit.username.value='alice';explicit.password.value='secret';explicit.submit();await settle();
  assert.equal(explicit.views().filter(view=>view.includes('notice')).length,0);
});
test('a login FactorSeal just filled is not offered for saving again',async()=>{
  const p=page();await settle();
  assert.equal(p.message({type:'fill',document:p.token(),username:'alice',password:'secret'}).filled,true);
  p.submit();
  assert.equal(p.messages.filter(m=>m.type==='save').length,0);
  assert.equal(p.message({type:'save-current'}).offered,true);
});
test('its own frames neither hide the login fields nor count as page changes',async()=>{
  const p=page();await settle();
  p.message({type:'notice'});
  const notice=p.frames.at(-1);notice.covers=()=>true;
  const scans=p.scans;
  p.mutate([{type:'attributes',target:p.frames[0],addedNodes:[],removedNodes:[]},{type:'childList',target:p.doc.documentElement,addedNodes:[notice],removedNodes:[p.frames[1]]}]);
  await settle();
  assert.equal(p.scans,scans);
  p.mutate([{type:'childList',target:p.doc.documentElement,addedNodes:[{}],removedNodes:[]}]);
  await settle();
  assert.equal(p.scans,scans+1);
  assert.equal(p.views().filter(view=>view.includes('field')).length,2);
  assert.ok(p.frames.slice(0,2).every(host=>host.style.display==='block'));
  assert.ok(!p.messages.some(m=>m.type==='invalidated'));
});
test('a press counts only while the pressed frame looks the way FactorSeal drew it',async()=>{
  const p=page({pending:true});await settle();
  const name=host=>new URL(host.shadow.children[0].src).search.slice(1);
  const notice=p.frames.find(host=>name(host)==='save');
  const [username,password]=p.frames.filter(host=>host!==notice);
  const pressed=(host,document=p.token())=>p.message({type:'pressed',document,page:host===notice?'notice':'field',frame:name(host)}).valid;
  assert.equal(pressed(password),true);
  assert.equal(pressed(notice),true);
  assert.equal(pressed(password,'forged'),false);
  assert.equal(p.message({type:'pressed',document:p.token(),page:'notice',frame:name(password)}).valid,false);
  for(const computed of [{opacity:'0.01'},{filter:'opacity(0)'},{visibility:'hidden'},{clipPath:'inset(50%)'}]){
    password.computed=computed;
    assert.equal(pressed(password),false,JSON.stringify(computed));
    assert.equal(pressed(username),true,JSON.stringify(computed));
  }
  delete password.computed;
  const drawn=username.getBoundingClientRect;
  username.getBoundingClientRect=()=>({left:0,top:0,width:1000,height:800,right:1000,bottom:800});
  assert.equal(pressed(username),false);
  assert.equal(pressed(notice),true);
  username.getBoundingClientRect=drawn;
  p.cover({});
  assert.equal(pressed(notice),false);
  p.cover(null);
  assert.equal(pressed(notice),true);
});
test('only the content script document owns its frames',async()=>{
  const p=page();await settle();
  assert.equal(p.message({type:'owns',document:p.token()}).valid,true);
  assert.equal(p.message({type:'owns',document:'forged'}).valid,false);
});
test('wrong document and changed form cannot fill',async()=>{
  const p=page();await settle();
  assert.equal(p.message({type:'fill',document:'stale',username:'u',password:'secret'}).filled,false);
  assert.equal(p.password.value,'');
  assert.equal(p.message({type:'check',document:p.token()}).valid,true);
  p.owner.action='https://evil.test/post';
  assert.equal(p.message({type:'fill',document:p.token(),username:'u',password:'secret'}).filled,false);
  assert.equal(p.password.value,'');
});
test('approved fill revalidates after username event handlers run',async()=>{
  const p=page();await settle();
  p.username.onInput=()=>{p.owner.action='https://evil.test/post';};
  assert.equal(p.message({type:'fill',document:p.token(),username:'u',password:'secret'}).filled,false);
  assert.equal(p.password.value,'');
});
test('approved stable form receives selected fields',async()=>{
  const p=page();await settle();
  assert.equal(p.message({type:'fill',document:p.token(),username:'alice',password:'secret'}).filled,true);
  assert.equal(p.username.value,'alice');assert.equal(p.password.value,'secret');
});
test('shared signed fixture verifies in Web Crypto',async()=>{
  const fixture=JSON.parse(await readFile(new URL('./fixtures/signed-request.json',import.meta.url),'utf8'));
  const key=await webcrypto.subtle.importKey('raw',Buffer.from(fixture.key,'hex'),'Ed25519',false,['verify']);
  assert.equal(await webcrypto.subtle.verify('Ed25519',key,Buffer.from(fixture.signature,'hex'),new TextEncoder().encode(fixture.payload)),true);
  assert.equal(await webcrypto.subtle.verify('Ed25519',key,Buffer.from(fixture.signature,'hex'),new TextEncoder().encode(fixture.payload+' ')),false);
});

test('Chromium manifest identity matches the startup native-host allowlist', async () => {
  const {readFile} = await import('node:fs/promises');
  const {createHash} = await import('node:crypto');
  const manifest = JSON.parse(await readFile(new URL('./manifest.chromium.json', import.meta.url), 'utf8'));
  const id = [...createHash('sha256').update(Buffer.from(manifest.key, 'base64')).digest().subarray(0, 16)]
    .flatMap(byte => [byte >> 4, byte & 15]).map(n => String.fromCharCode(97 + n)).join('');
  const registration = await readFile(new URL('../../src/browser/registration.rs', import.meta.url), 'utf8');
  assert.equal(id, /CHROMIUM_ID: &str = "([a-p]{32})"/.exec(registration)[1]);
});
