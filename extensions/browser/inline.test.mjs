import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
const load=name=>readFile(new URL(`./${name}`,import.meta.url),'utf8');
const [labels,field,notice]=await Promise.all(['labels.js','field.js','notice.js'].map(load));
function inline(source,{search='',states=[],pending=[],saved=true}={}) {
  const sent=[],nodes=new Map();
  const element=id=>{if(!nodes.has(id))nodes.set(id,{id,hidden:true,textContent:''});return nodes.get(id);};
  const context=vm.createContext({document:{getElementById:element},location:{hash:'#doc',search},setTimeout:fn=>queueMicrotask(fn),
    browser:{runtime:{sendMessage:async message=>{
      sent.push(message);
      if(message.type==='notice-status')return states.shift();
      if(message.type==='notice-pending')return {pending:pending.shift()??false};
      return {accepted:message.type!=='notice-save' || saved};
    }}}});
  vm.runInContext(labels,context);vm.runInContext(source,context);
  return {element,sent};
}
const settle=async()=>{for(let i=0;i<20;i++)await new Promise(resolve=>setImmediate(resolve));};
test('the field button asks for its own document to be filled, naming its frame',async()=>{
  const p=inline(field,{search:'?f1'});
  p.element('fill').onclick();
  assert.equal(JSON.stringify(p.sent),'[{"type":"fill-field","document":"doc","frame":"f1"}]');
});
test('the save question offers Save and Not now for its own document',async()=>{
  const p=inline(notice,{search:'?save',pending:[true]});
  assert.equal(p.element('status').textContent,'Save this login in FactorSeal?');
  assert.equal(p.element('choices').hidden,false);
  await p.element('save').onclick();p.element('later').onclick();
  assert.deepEqual(p.sent.filter(message=>message.type!=='notice-pending').map(message=>`${message.type}:${message.document}:${message.frame}`),['notice-save:doc:save','notice-close:doc:save']);
});
test('the save question closes once its login is no longer waiting',async()=>{
  const p=inline(notice,{search:'?save',pending:[true,true]});
  await settle();
  assert.deepEqual(p.sent.map(message=>message.type),['notice-pending','notice-pending','notice-pending','notice-close']);
});
test('a refused Save closes the question',async()=>{
  const p=inline(notice,{search:'?save',pending:Array(50).fill(true),saved:false});
  await p.element('save').onclick();
  assert.ok(p.sent.some(message=>message.type==='notice-close'));
});
test('the status notice follows the request and closes once it is over',async()=>{
  const p=inline(notice,{states:[{status:'awaiting_approval',active:true},{status:'no_match',active:false}]});
  await settle();
  assert.equal(p.element('status').textContent,'No matching login found.');
  assert.equal(p.element('choices').hidden,true);
  assert.deepEqual(p.sent.map(message=>message.type),['notice-status','notice-status','notice-close']);
});
test('a filled login closes the status notice right away',async()=>{
  const p=inline(notice,{states:[{status:'Filled',active:false}]});
  await settle();
  assert.deepEqual(p.sent.map(message=>message.type),['notice-status','notice-close']);
});
