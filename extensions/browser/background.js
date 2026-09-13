/* Both browsers run this same coordinator. Only manifests/background loading differ. */
if (typeof importScripts === 'function') importScripts('core.js');
const api = globalThis.browser || globalThis.chrome;
const core = globalThis.FactorSealCore;
let port, waiting, session, sequence=0, active, keyPromise;
let status='Disconnected';
let queue=Promise.resolve();
let recovery, nextRecovery=0;
const connectionFailures=new Set(['desktop_missing','desktop_unavailable','native_disconnected','native_timeout']);
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const serialized=fn=>{ const result=queue.then(fn); queue=result.catch(()=>{}); return result; };
function rpc(request) {
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{waiting=null;port?.disconnect();reject(new Error('native_timeout'));},10000);
    waiting={resolve:value=>{clearTimeout(timer);resolve(core.validateResponse(value));},reject:error=>{clearTimeout(timer);reject(error);}};
    port.postMessage(request);
  });
}
async function keys() {
  if (!keyPromise) keyPromise=(async()=>{
    if (api.storage.local.setAccessLevel) await api.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'});
    const saved=(await api.storage.local.get('pairing')).pairing;
    if (saved) return {key:await crypto.subtle.importKey('jwk',saved.private,{name:'Ed25519'},false,['sign']),public:saved.public};
    const pair=await crypto.subtle.generateKey({name:'Ed25519'},true,['sign','verify']);
    const publicKey=core.hex(await crypto.subtle.exportKey('raw',pair.publicKey));
    await api.storage.local.set({pairing:{private:await crypto.subtle.exportKey('jwk',pair.privateKey),public:publicKey}});
    return {key:pair.privateKey,public:publicKey};
  })().catch(error=>{keyPromise=null;throw error;});
  return keyPromise;
}
async function connect() {
  if (port && session) return;
  const previous=port;port=null;previous?.disconnect();
  const connected=api.runtime.connectNative('dev.factorseal.browser');port=connected;
  connected.onMessage.addListener(value=>{if(port!==connected)return;const w=waiting;waiting=null;try{w?.resolve(value);}catch(e){w?.reject(e);}});
  connected.onDisconnect.addListener(()=>{
    const error=api.runtime.lastError?.message||'';
    if(port!==connected)return;
    const reason=/specified native messaging host not found|no such native application/i.test(error)?'desktop_missing':'native_disconnected';
    const w=waiting;waiting=null;session=null;port=null;active=null;status='Disconnected';
    w?.reject(new Error(reason));
  });
  const hello=await rpc({type:'hello',version:1});
  if (hello.type!=='hello') throw new Error(hello.reason||'desktop_unavailable');
  session=hello.session;sequence=0;
}
function recoverConnection() {
  if(active || recovery || !connectionFailures.has(status) || Date.now()<nextRecovery)return;
  nextRecovery=Date.now()+3000;
  recovery=serialized(async()=>{
    if(active || !connectionFailures.has(status))return;
    try {
      await connect();
      if(!active)status='idle';
    } catch(error) {
      if(!active)status=String(error.message||'desktop_unavailable');
    }
  }).finally(()=>{recovery=null;});
}
function send(action,idleOnly=false) {
  return serialized(async()=>{
    if(idleOnly&&active)return;
    await connect(); const pair=await keys();
    const browser=core.browserKind(globalThis.navigator,typeof api.runtime.getBrowserInfo==='function');
    const payload=JSON.stringify({version:1,session,sequence:++sequence,action,browser});
    const signature=core.hex(await crypto.subtle.sign('Ed25519',pair.key,new TextEncoder().encode(payload)));
    if(idleOnly&&active)return;
    return rpc({type:'signed',message:{key:pair.public,payload,signature}});
  });
}
async function current(flow) {
  const tab=await api.tabs.get(flow.tab);
  if (!tab.active || core.origin(tab.url)!==flow.origin) return false;
  const check=await api.tabs.sendMessage(flow.tab,{type:'check',document:flow.document},{frameId:0});
  return check?.valid===true && check.document===flow.document;
}
async function cancel() {
  if (!active) return;
  active=null;
  try {await send({type:'cancel'});} catch {}
}
async function run(action,context) {
  if (active) return {status:'Another browser request is pending'};
  const flow={...context,kind:action.type,token:crypto.randomUUID()}; active=flow;
  status='connecting';
  try {
    let response=await send(action);
    const deadline=Date.now()+300000;
    while (active===flow && Date.now()<deadline) {
      if (response.type==='finished') {
        status=response.reason==='done' && action.type==='save'?'saved':response.reason;
        if(response.reason==='done' && action.type==='pair'){
          await api.storage.local.set({paired:true});
          await register().catch(()=>{});
          // Start watching the current page too, without requiring a reload.
          try {
            const [tab]=await api.tabs.query({active:true,currentWindow:true});
            core.origin(tab?.url);
            if(await api.permissions.contains({origins:['https://*/*']}))
              await api.scripting.executeScript({target:{tabId:tab.id},files:['content.js']});
          } catch {}
        }
        if((response.reason==='done' && action.type==='revoke') || ['pair_required','revoked','vault_rejected'].includes(response.reason))await api.storage.local.set({paired:false});
        if(response.reason==='unauthorized')port?.disconnect();break;
      }
      if (response.type==='fill') {
        if (context && await current(flow) && active===flow) {
          // Only the original document receives values; it rechecks the form too.
          await api.tabs.sendMessage(flow.tab,{type:'fill',document:flow.document,username:core.decode(response.username),password:core.decode(response.password)},{frameId:0});
          status='Filled';
        } else {status='Page changed; fill discarded';}
        response=null;break;
      }
      if (response.type==='context') {
        if (!context || !await current(flow) || active!==flow) {await cancel();break;}
        response=await send({type:'confirm',nonce:response.nonce});
      } else {
        status=response.state;
        await sleep(350);
        if (active!==flow) break;
        response=await send({type:'poll'});
      }
    }
    if (Date.now()>=deadline) await cancel();
  } catch (error) {status=error.message==='NotSupportedError'?'This browser does not support Ed25519 pairing':String(error.message||'Request failed');}
  finally {if(active===flow)active=null;}
  return {status};
}
async function register() {
  if((await api.storage.local.get('paired')).paired!==true)return;
  if (!await api.permissions.contains({origins:['https://*/*']})) return;
  const registered=await api.scripting.getRegisteredContentScripts();
  if (!registered.some(s=>s.id==='factorseal-login')) await api.scripting.registerContentScripts([{id:'factorseal-login',matches:['https://*/*'],js:['content.js'],runAt:'document_idle',allFrames:false}]);
}
api.permissions.onAdded.addListener(()=>{void register().catch(()=>{});});
api.permissions.onRemoved.addListener(()=>{void cancel();void api.scripting.unregisterContentScripts({ids:['factorseal-login']}).catch(()=>{});});
api.runtime.onInstalled.addListener(()=>{void register().catch(()=>{});});
void register().then(async()=>{
  if((await api.storage.local.get('paired')).paired===true)await send({type:'poll'},true);
}).catch(()=>{});
api.tabs.onRemoved.addListener(tab=>{if(active?.tab===tab)void cancel();});
api.tabs.onActivated.addListener(({tabId})=>{if(active?.tab!=null && active.tab!==tabId)void cancel();});
api.windows.onFocusChanged.addListener(windowId=>{if(windowId>=0 && active?.window!=null && active.window!==windowId)void cancel();});
api.tabs.onUpdated.addListener((tab,change)=>{if(active?.tab===tab && active.kind!=='save' && (change.status==='loading'||change.url))void cancel();});
api.runtime.onMessage.addListener((message,sender,reply)=>{
  (async()=>{
    if (sender.url===api.runtime.getURL('popup.html') && !sender.tab) {
      if (message.type==='status') {
        recoverConnection();
        const paired=(await api.storage.local.get('paired')).paired===true;
        const [tab]=await api.tabs.query?.({active:true,currentWindow:true})||[];
        let site;try{site=core.origin(tab?.url);}catch{}
        return {status,paired,platform:(await api.runtime.getPlatformInfo?.())?.os,pending:active?.kind||null,profile:(await keys()).public.slice(0,16),
          detection:await api.permissions.contains({origins:['https://*/*']}),site,
          paused:site?((await api.storage.local.get('paused')).paused||[]).includes(site):false};
      }
      if (message.type==='pair') {void run({type:'pair'});return {status:'Approve pairing in Desktop'};}
      if (message.type==='revoke') {void run({type:'revoke'});return {status:'Approve disconnection in Desktop'};}
      if (message.type==='cancel') {await cancel();return {status:'Cancelled'};}
      if(message.type==='save-page'){
        const [tab]=await api.tabs.query({active:true,currentWindow:true});
        core.origin(tab?.url);
        await api.scripting.executeScript({target:{tabId:tab.id},files:['content.js']});
        const result=await api.tabs.sendMessage(tab.id,{type:'save-current'},{frameId:0});
        if(!result?.offered)status='No complete login form found on this page.';
        return {status};
      }
      if (message.type==='retry') {const [tab]=await api.tabs.query({active:true,currentWindow:true});await api.scripting.executeScript({target:{tabId:tab.id},files:['content.js']});await api.tabs.sendMessage(tab.id,{type:'retry'},{frameId:0});return {status:'Checking page'};}
      if (message.type==='pause') {
        const [tab]=await api.tabs.query({active:true,currentWindow:true});
        const site=core.origin(tab.url);const paused=(await api.storage.local.get('paused')).paused||[];
        await api.storage.local.set({paused:paused.includes(site)?paused.filter(x=>x!==site):[...paused,site]});await cancel();return {status:'Site pause toggled'};
      }
      throw new Error('unknown_action');
    }
    if (sender.id!==api.runtime.id || sender.frameId!==0 || !sender.tab || !['detected','invalidated','save'].includes(message.type) || typeof message.document!=='string' || message.document.length>128) throw new Error('invalid_sender');
    if (message.type==='invalidated') {
      if(active?.kind!=='save' && active?.tab===sender.tab.id && active.document===message.document)await cancel();
      return {accepted:true};
    }
    const tab=await api.tabs.get(sender.tab.id);const win=await api.windows.get(tab.windowId);
    if (!tab.active || !win.focused) return {accepted:false};
    const site=core.origin(sender.url);if(core.origin(tab.url)!==site)return {accepted:false};
    if (((await api.storage.local.get('paused')).paused||[]).includes(site)) return {accepted:false};
    if(message.type==='save'){
      if((await api.storage.local.get('paired')).paired!==true || typeof message.username!=='string' || typeof message.password!=='string'
        || !message.username || !message.password || new TextEncoder().encode(message.username).length>512 || new TextEncoder().encode(message.password).length>4096)return {accepted:false};
      if(active){
        if(active.kind!=='detect' || active.tab!==tab.id || active.document!==message.document)return {accepted:false};
        await cancel();
      }
      const password=btoa(String.fromCharCode(...new TextEncoder().encode(message.password)));
      void run({type:'save',origin:site,document:message.document,username:message.username,password},{tab:tab.id,window:tab.windowId,origin:site,document:message.document});
      return {accepted:true};
    }
    if(active)return {accepted:false};
    void run({type:'detect',origin:site,document:message.document},{tab:tab.id,window:tab.windowId,origin:site,document:message.document});
    return {accepted:true};
  })().then(reply,()=>reply({status:'Request unavailable',accepted:false}));
  return true;
});
