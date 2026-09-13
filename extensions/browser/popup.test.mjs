import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
const source=await readFile(new URL('./popup.js',import.meta.url),'utf8');
function popup(state,{allowed=true}={}){
  const calls=[];
  const nodes=new Map();
  const element=id=>{if(!nodes.has(id))nodes.set(id,{id,hidden:false,disabled:false,textContent:''});return nodes.get(id);};
  const buttons=['pair','enable','retry','pause','cancel','revoke'].map(element);
  const context=vm.createContext({document:{getElementById:element,querySelectorAll:()=>buttons},browser:{runtime:{sendMessage:async message=>{calls.push(message.type);return state;}},permissions:{request:async()=>{calls.push('site-permission');return allowed;}}},setTimeout:()=>{}});
  vm.runInContext(source,context);context.render(state);
  return {element,render:context.render,calls};
}
for(const allowed of [true,false])test(`pairing requests site access in the same click (allowed: ${allowed})`,async()=>{
  const {element,calls}=popup({paired:false,status:'idle'},{allowed});
  calls.length=0;
  await element('pair').onclick();
  assert.deepEqual(calls.slice(0,2),['site-permission','pair']);
});
test('unpaired popup offers pairing without login or profile controls',()=>{
  const {element}=popup({paired:false,pending:null,status:'Disconnected'});
  assert.equal(element('onboarding').hidden,false);
  assert.equal(element('pair').hidden,false);
  for(const id of ['controls','profile','cancel','pairing-key'])assert.equal(element(id).hidden,true);
});
test('pairing progress shows Desktop guidance and cancellation',()=>{
  const {element}=popup({paired:false,pending:'pair',status:'awaiting_unseal',profile:'abc'});
  assert.equal(element('pair').hidden,true);
  assert.equal(element('controls').hidden,true);
  assert.equal(element('cancel').hidden,false);
  assert.equal(element('pairing-key').hidden,false);
  assert.match(element('heading').textContent,/Desktop/);
});
test('pairing waits for Desktop to respond before directing the user there',()=>{
  const {element,render}=popup({paired:false,pending:'pair',status:'connecting'});
  assert.equal(element('heading').textContent,'Connecting to Desktop…');
  assert.equal(element('pair').hidden,true);
  assert.equal(element('cancel').hidden,false);
  render({paired:false,pending:'pair',status:'awaiting_unseal'});
  assert.equal(element('heading').textContent,'Continue in Desktop');
  render({paired:false,pending:null,status:'desktop_unavailable'});
  assert.equal(element('pair').hidden,false);
  assert.match(element('status').textContent,/Open FactorSeal Desktop/);
});
for(const [platform,label] of [['win','Windows'],['mac','macOS'],['linux','Linux'],['cros','Desktop']])test(`installation guidance for ${platform}`,()=>{
  const {element,render}=popup({paired:false,status:'desktop_missing',platform});
  assert.equal(element('install').hidden,false);
  assert.ok(element('install').textContent.endsWith(label));
  assert.equal(element('pair').textContent,'Try again');
  assert.match(element('status').textContent,/Install FactorSeal Desktop/);
  render({paired:false,pending:'pair',status:'connecting',platform});
  assert.equal(element('install').hidden,true);
  render({paired:true,status:'done',platform});
  assert.equal(element('install').hidden,true);
});
test('installation guidance stays hidden for ordinary connection failures and normal states',()=>{
  const {element,render}=popup({paired:false,status:'desktop_missing'});
  for(const status of ['desktop_unavailable','native_disconnected','native_timeout','Disconnected','done','awaiting_unseal','awaiting_approval']){
    render({paired:false,status});
    assert.equal(element('install').hidden,true,status);
  }
});
test('approved pairing reveals permission onboarding, then page controls; revocation resets it',()=>{
  const {element,render}=popup({paired:true,pending:null,detection:false,status:'done'});
  assert.equal(element('onboarding').hidden,true);
  assert.equal(element('detection').hidden,false);
  assert.equal(element('site-controls').hidden,true);
  render({paired:true,detection:true,paused:true,site:'https://example.com',status:'idle'});
  assert.equal(element('detection').hidden,true);
  assert.equal(element('site-controls').hidden,false);
  assert.equal(element('pause').textContent,'Resume on this site');
  render({paired:false,status:'revoked'});
  assert.equal(element('controls').hidden,true);
  assert.equal(element('pair').hidden,false);
});
