import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import {webcrypto} from 'node:crypto';
await import('./core.js');
const {origin,validateResponse,decode}=globalThis.FactorSealCore;
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
function page({hidden=false,crossOrigin=false,newPassword=false,confirmation=false}={}) {
  let listener, detected=0;
  const events={},messages=[];
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
  const doc={visibilityState:'visible',documentElement:{},querySelectorAll:()=>[password,...(confirm?[confirm]:[])],addEventListener:(name,fn)=>{events[name]=fn;},elementFromPoint:(_x,y)=>y>85?confirm:y>45?password:username};
  const window={addEventListener:()=>{}};window.top=window;
  const context={crypto:webcrypto,URL,Event,TextEncoder,HTMLInputElement:Input,document:doc,innerWidth:1000,innerHeight:800,location:{protocol:'https:',origin:'https://example.com',href:'https://example.com/login'},window,
    getComputedStyle:()=>({visibility:'visible',display:'block',opacity:'1'}),setTimeout:fn=>{queueMicrotask(fn);},MutationObserver:class{observe(){}},
    browser:{runtime:{id:'test',sendMessage:async message=>{messages.push(message);if(message.type==='detected')detected++;return {accepted:true};},onMessage:{addListener:f=>{listener=f;}}}}};
  vm.runInNewContext(script,context);
  const message=payload=>{let result;listener(payload,{id:'test'},r=>result=r);return result;};
  return {username,password,confirm,owner,context,message,messages,edit:()=>events.input({isTrusted:true}),submit:(trusted=true)=>events.submit({isTrusted:trusted,target:owner}),get detected(){return detected;}};
}
for(const registration of [false,true])test(`offers submitted ${registration?'registration':'login'} credentials once`,async()=>{
  const p=page({newPassword:registration,confirmation:registration});
  p.username.value='alice';p.password.value='secret';if(p.confirm)p.confirm.value='secret';
  await new Promise(r=>setImmediate(r));
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
test('hidden, cross-origin, and signup forms do not prompt',async()=>{
  for(const options of [{hidden:true},{crossOrigin:true},{newPassword:true}]){const p=page(options);await new Promise(r=>setImmediate(r));assert.equal(p.detected,0);}
});
test('one prompt per document; wrong document and changed form cannot fill',async()=>{
  const p=page();await new Promise(r=>setImmediate(r));assert.equal(p.detected,1);
  assert.equal(p.message({type:'fill',document:'stale',username:'u',password:'secret'}).filled,false);
  assert.equal(p.password.value,'');
  // Capture the content script's actual document token from its outbound message.
  let token;
  const q=page();q.context.browser.runtime.sendMessage=async m=>{token=m.document;return {accepted:true};};
  await new Promise(r=>setImmediate(r));
  assert.equal(q.message({type:'check',document:token}).valid,true);
  q.owner.action='https://evil.test/post';
  assert.equal(q.message({type:'fill',document:token,username:'u',password:'secret'}).filled,false);
  assert.equal(q.password.value,'');
});
test('approved fill revalidates after username event handlers run',async()=>{
  let token;const p=page();p.context.browser.runtime.sendMessage=async m=>{token=m.document;return {accepted:true};};await new Promise(r=>setImmediate(r));
  p.username.onInput=()=>{p.owner.action='https://evil.test/post';};
  assert.equal(p.message({type:'fill',document:token,username:'u',password:'secret'}).filled,false);
  assert.equal(p.password.value,'');
});
test('approved stable form receives selected fields',async()=>{
  let token;const p=page();p.context.browser.runtime.sendMessage=async m=>{token=m.document;return {accepted:true};};await new Promise(r=>setImmediate(r));
  assert.equal(p.message({type:'fill',document:token,username:'alice',password:'secret'}).filled,true);
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
