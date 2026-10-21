/* Both browsers run this same coordinator. Only manifests/background loading differ. */
if (typeof importScripts === 'function') importScripts('core.js');
const api = globalThis.browser || globalThis.chrome;
const core = globalThis.FactorSealCore;
let port, waiting, session, sequence=0, active, keyPromise;
let status='Disconnected';
// The tab and site a request's status is about; the popup shows it only there.
let statusScope=null;
let queue=Promise.resolve();
let recovery, nextRecovery=0;
// A save the person asked for from the popup, which keeps the focus from the page.
let explicitSave=null;
const pendingSaves=new Map();
const pages=[api.runtime.getURL('field.html'),api.runtime.getURL('notice.html')];
const connectionFailures=new Set(['desktop_missing','desktop_unavailable','native_disconnected','native_timeout']);
const imagePart=43688;
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const serialized=fn=>{ const result=queue.then(fn); queue=result.catch(()=>{}); return result; };
// Closing the port ourselves does not fire its onDisconnect, so forget it and
// its session here; the next request then connects again.
function disconnect() {const closed=port;port=null;session=null;closed?.disconnect();}
function rpc(request) {
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{waiting=null;disconnect();reject(new Error('native_timeout'));},10000);
    waiting={resolve:value=>{clearTimeout(timer);resolve(core.validateResponse(value));},reject:error=>{clearTimeout(timer);reject(error);}};
    // The host can be gone (Desktop restarted) before onDisconnect fires; the
    // browser then throws here. Handle it as that disconnect, so recovery
    // reconnects instead of leaving the raw error as the status.
    try { port.postMessage(request); }
    catch { waiting=null;session=null;port=null;active=null;status='Disconnected';clearTimeout(timer);reject(new Error('native_disconnected')); }
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
async function sendImage(image,flow) {
  const size=image.length/4*3-(image.endsWith('==')?2:image.endsWith('=')?1:0);
  let response;
  for(let start=0;start<image.length && active===flow;start+=imagePart){
    response=await send({type:'image',size,data:image.slice(start,start+imagePart)});
    if(response.type!=='state')break;
  }
  return response;
}
async function run(action,context,image) {
  if (active) return {status:'Another browser request is pending'};
  const flow={...context,kind:action.type,token:crypto.randomUUID()}; active=flow;
  status='connecting';statusScope=context?{tab:context.tab,origin:context.origin}:null;
  try {
    let response=await send(action);
    // Desktop forgets a session when it restarts or after ten idle minutes,
    // and refuses it before acting on anything. Connect again and ask once more.
    if(response.type==='finished' && response.reason==='unauthorized'){disconnect();response=await send(action);}
    if(image && response.type==='state')response=await sendImage(image,flow);
    const deadline=Date.now()+300000;
    while (active===flow && Date.now()<deadline) {
      if (response.type==='finished') {
        status=(response.reason==='done' && {save:'saved',one_time:'one_time_saved'}[action.type])||response.reason;
        if(response.reason==='done' && action.type==='pair'){
          await api.storage.local.set({paired:true});
          await register().catch(()=>{});
          await refreshTabs();
          // Start watching the current page too, without requiring a reload.
          try {
            const [tab]=await api.tabs.query({active:true,currentWindow:true});
            core.origin(tab?.url);
            if(await api.permissions.contains({origins:['https://*/*']}))
              await api.scripting.executeScript({target:{tabId:tab.id},files:['content.js']});
          } catch {}
        }
        if((response.reason==='done' && action.type==='revoke') || ['pair_required','revoked','vault_rejected'].includes(response.reason)){await api.storage.local.set({paired:false});await refreshTabs();}
        if(response.reason==='unauthorized')disconnect();break;
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
async function settings(site) {
  const {paired,paused}=await api.storage.local.get(['paired','paused']);
  return {paired:paired===true,paused:(paused||[]).includes(site)};
}
async function tell(tab,message) {
  return api.tabs.sendMessage(tab,message,{frameId:0}).catch(()=>null);
}
async function start(action,context,image) {
  void run(action,context,image);
  await tell(context.tab,{type:'notice'});
}
async function fill(tab,site,document,explicit) {
  const {paired,paused}=await settings(site);
  if(!tab.active || active || !paired || (paused && !explicit))return false;
  await start({type:'detect',origin:site,document},{tab:tab.id,window:tab.windowId,origin:site,document});
  return true;
}
function related(site,origin) {
  const [host,saved]=[site,origin].map(url=>new URL(url).hostname.replace(/^www\./,''));
  return host===saved || host.endsWith(`.${saved}`) || saved.endsWith(`.${host}`);
}
function clearPendingSave(tab) {
  const save=pendingSaves.get(tab);
  if(save)clearTimeout(save.timer);
  pendingSaves.delete(tab);
}
function pendingSave(tab,site) {
  const save=pendingSaves.get(tab);
  if(save && Date.now()>=save.until)clearPendingSave(tab);
  return save && Date.now()<save.until && related(site,save.origin)?save:null;
}
async function refreshTabs() {
  for(const tab of await api.tabs.query({}).catch(()=>[]))void tell(tab.id,{type:'site-changed'});
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
api.tabs.onRemoved.addListener(tab=>{if(active?.tab===tab)void cancel();clearPendingSave(tab);});
api.tabs.onActivated.addListener(({tabId})=>{if(active?.tab!=null && active.tab!==tabId)void cancel();});
api.windows.onFocusChanged.addListener(windowId=>{if(windowId>=0 && active?.window!=null && active.window!==windowId)void cancel();});
api.tabs.onUpdated.addListener((tab,change)=>{if(active?.tab===tab && !['save','one_time'].includes(active.kind) && (change.status==='loading'||change.url))void cancel();});
api.runtime.onMessage.addListener((message,sender,reply)=>{
  (async()=>{
    const popupUrl=api.runtime.getURL('popup.html');
    // The browser supplies a tab for our own popup opened as a page too.
    // Only that extension's top-level page may use the popup controls.
    const popupTab=sender.id===api.runtime.id && sender.frameId===0 && sender.tab?.url===popupUrl;
    if (sender.url===popupUrl && (!sender.tab || popupTab)) {
      if (message.type==='status') {
        recoverConnection();
        const paired=(await api.storage.local.get('paired')).paired===true;
        const [tab]=await api.tabs.query?.({active:true,currentWindow:true})||[];
        let site;try{site=core.origin(tab?.url);}catch{}
        // Another page's result ("Request denied.") would read as this page's.
        const elsewhere=!active && statusScope && (statusScope.tab!==tab?.id || statusScope.origin!==site) && !connectionFailures.has(status);
        return {status:elsewhere?'idle':status,paired,platform:(await api.runtime.getPlatformInfo?.())?.os,pending:active?.kind||null,profile:(await keys()).public.slice(0,16),
          detection:await api.permissions.contains({origins:['https://*/*']}),site,
          paused:site?((await api.storage.local.get('paused')).paused||[]).includes(site):false};
      }
      if (message.type==='pair') {void run({type:'pair'});return {status:'Approve pairing in Desktop'};}
      if (message.type==='revoke') {void run({type:'revoke'});return {status:'Approve disconnection in Desktop'};}
      if (message.type==='cancel') {await cancel();return {status:'Cancelled'};}
      if(message.type==='save-page'){
        const [tab]=await api.tabs.query({active:true,currentWindow:true});
        const origin=core.origin(tab?.url);
        await api.scripting.executeScript({target:{tabId:tab.id},files:['content.js']});
        explicitSave={tab:tab.id,until:Date.now()+5000};
        const result=await api.tabs.sendMessage(tab.id,{type:'save-current'},{frameId:0});
        if(!result?.offered){explicitSave=null;status='No complete login form found on this page.';statusScope={tab:tab.id,origin};}
        return {status,offered:!!result?.offered};
      }
      if(message.type==='one-time'){
        const [tab]=await api.tabs.query({active:true,currentWindow:true});
        const origin=core.origin(tab?.url);
        const picture=await api.tabs.captureVisibleTab(tab.windowId,{format:'jpeg',quality:92}).catch(()=>null);
        if(typeof picture!=='string' || !picture.startsWith('data:image/jpeg;base64,')){status='capture_failed';statusScope={tab:tab.id,origin};return {status};}
        await start({type:'one_time',origin},{tab:tab.id,window:tab.windowId,origin},picture.slice(picture.indexOf(',')+1));
        return {status:'connecting'};
      }
      if (message.type==='fill') {
        const [tab]=await api.tabs.query({active:true,currentWindow:true});
        const origin=core.origin(tab?.url);
        await api.scripting.executeScript({target:{tabId:tab.id},files:['content.js']});
        const result=await tell(tab.id,{type:'find'});
        if(!result?.document){status='No complete login form found on this page.';statusScope={tab:tab.id,origin};return {status,found:false};}
        return {status:'connecting',found:await fill(tab,origin,result.document,true)};
      }
      if (message.type==='pause') {
        const [tab]=await api.tabs.query({active:true,currentWindow:true});
        const site=core.origin(tab.url);const paused=(await api.storage.local.get('paused')).paused||[];
        await api.storage.local.set({paused:paused.includes(site)?paused.filter(x=>x!==site):[...paused,site]});await cancel();await refreshTabs();return {status:'Site pause toggled'};
      }
      throw new Error('unknown_action');
    }
    if (sender.id===api.runtime.id && sender.tab && pages.includes(sender.url?.split(/[?#]/)[0]) && typeof message.document==='string' && typeof message.frame==='string') {
      const tab=await api.tabs.get(sender.tab.id);
      const site=core.origin(tab.url);
      const pressed={'fill-field':'field','notice-save':'notice'}[message.type];
      if(!(await tell(tab.id,{type:pressed?'pressed':'owns',document:message.document,page:pressed,frame:message.frame}))?.valid)return {accepted:false};
      if(message.type==='fill-field')return {accepted:await fill(tab,site,message.document)};
      if(message.type==='notice-status')return {status:statusScope?.tab===tab.id?status:'idle',active:active?.tab===tab.id};
      if(message.type==='notice-pending'){
        const {paired,paused}=await settings(site);
        return {pending:paired && !paused && !!pendingSave(tab.id,site)};
      }
      if(message.type==='notice-close'){
        if(message.frame==='save')clearPendingSave(tab.id);
        await tell(tab.id,{type:'close-notice'});
        return {accepted:true};
      }
      if(message.type==='notice-save'){
        const {paired,paused}=await settings(site);
        const save=pendingSave(tab.id,site);
        if(!save || active || !paired || paused)return {accepted:false};
        clearPendingSave(tab.id);
        await start({type:'save',origin:save.origin,document:message.document,username:save.username,password:save.password},{tab:tab.id,window:tab.windowId,origin:site,document:message.document});
        return {accepted:true};
      }
      throw new Error('unknown_action');
    }
    if (sender.id!==api.runtime.id || sender.frameId!==0 || !sender.tab || !['field','pending','invalidated','save'].includes(message.type) || typeof message.document!=='string' || message.document.length>128) throw new Error('invalid_sender');
    if (message.type==='invalidated') {
      if(active?.kind!=='save' && active?.tab===sender.tab.id && active.document===message.document)await cancel();
      return {accepted:true};
    }
    const tab=await api.tabs.get(sender.tab.id);
    const site=core.origin(sender.url);if(core.origin(tab.url)!==site)return {accepted:false};
    const {paired,paused}=await settings(site);
    if(message.type==='field')return {show:paired && !paused};
    if(message.type==='pending')return {save:paired && !paused && !!pendingSave(tab.id,site)};
    const win=await api.windows.get(tab.windowId);
    // Only a page the person is looking at may ask, or a save they asked for
    // from the popup just now, once.
    const explicit=explicitSave?.tab===tab.id && Date.now()<explicitSave.until;
    if(explicit)explicitSave=null;
    if (!tab.active || (!win.focused && !explicit) || (paused && !explicit) || !paired || typeof message.username!=='string' || typeof message.password!=='string'
      || !message.username || !message.password || new TextEncoder().encode(message.username).length>512 || new TextEncoder().encode(message.password).length>4096)return {accepted:false};
    const password=btoa(String.fromCharCode(...new TextEncoder().encode(message.password)));
    if(!explicit){
      clearPendingSave(tab.id);
      // Navigation can leave no content script to poll for expiration.
      const timer=setTimeout(()=>clearPendingSave(tab.id),120000);
      pendingSaves.set(tab.id,{origin:site,username:message.username,password,until:Date.now()+120000,timer});
      return {accepted:true,ask:true};
    }
    if(active){
      if(active.kind!=='detect' || active.tab!==tab.id || active.document!==message.document)return {accepted:false};
      await cancel();
    }
    await start({type:'save',origin:site,document:message.document,username:message.username,password},{tab:tab.id,window:tab.windowId,origin:site,document:message.document});
    return {accepted:true};
  })().then(reply,()=>reply({status:'Request unavailable',accepted:false}));
  return true;
});
