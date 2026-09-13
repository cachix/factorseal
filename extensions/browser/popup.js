const api=globalThis.browser||globalThis.chrome;
const element=id=>document.getElementById(id);
const status=element('status');
const labels={awaiting_unseal:'Unseal FactorSeal in Desktop to continue.',matching:'Checking for matching logins…',awaiting_approval:'Approve this request in Desktop.',awaiting_context:'Checking the login page…',releasing:'Filling your login…',saving:'Saving approval…',pair_required:'Pair this browser profile with Desktop first.',no_match:'No matching login found.',denied:'Request denied.',cancelled:'Request cancelled.',expired:'Request expired. Try again.',sealed:'Vault sealed.',revoked:'Browser profile disconnected.',done:'',busy:'Another request is pending.',vault_rejected:'The vault rejected this request. Pair with Desktop to try again.',desktop_unavailable:'Open FactorSeal Desktop, then try again.',native_disconnected:'Could not connect. Open FactorSeal Desktop and try again.',unauthorized:'Connection expired. Try again.',idle:'',Disconnected:'',Cancelled:'Request cancelled.'};
let busy=false,notice='',previousStatus;
function render(state) {
  const paired=state.paired===true;
  const pending=Boolean(state.pending);
  const unavailable=['desktop_missing','desktop_unavailable','native_disconnected','native_timeout'].includes(state.status)&&!pending;
  const platform={win:'Windows',mac:'macOS',linux:'Linux'}[state.platform];
  element('install').hidden=pending||state.status!=='desktop_missing';
  element('install').textContent=platform?`Get FactorSeal for ${platform}`:'Get FactorSeal Desktop';
  element('onboarding').hidden=paired;
  element('controls').hidden=!paired;
  element('profile').hidden=!paired;
  element('heading').textContent=pending?(state.status==='connecting'?'Connecting to Desktop…':'Continue in Desktop'):'Connect to Desktop';
  element('intro').hidden=pending||unavailable;
  element('pair').textContent=unavailable?'Try again':'Pair with Desktop';
  element('pair').hidden=pending;
  element('cancel').hidden=!pending;
  element('detection').hidden=!paired||state.detection;
  element('site-controls').hidden=!paired||!state.detection;
  element('pause').textContent=state.paused?'Resume on this site':'Pause on this site';
  for(const id of ['retry','pause','revoke','enable'])element(id).disabled=pending||busy||(id==='pause'&&!state.site);
  element('pairing-key').hidden=paired||!pending;
  const key=state.profile?`Profile key: ${state.profile}…`:'';
  element('profile-key').textContent=key;
  element('pending-profile-key').textContent=key;
  if(state.status!==previousStatus){notice='';previousStatus=state.status;}
  status.textContent=notice||(state.status==='desktop_missing'?'Install FactorSeal Desktop, then open it and try again. Already installed? Open it once to finish browser setup.':state.status==='connecting'?(paired?'Connecting to Desktop…':''):state.status==='native_timeout'?'Desktop did not respond. Open FactorSeal and try again.':(labels[state.status]??state.status??''));
}
async function refresh() {try{render(await api.runtime.sendMessage({type:'status'}));}catch{status.textContent='Extension unavailable. Reload it and try again.';}}
for(const button of document.querySelectorAll('button'))button.onclick=async()=>{
  if(busy)return;busy=true;button.disabled=true;
  try {
    if(button.id==='pair'){
      // Request from the click itself: browsers require a user gesture.
      await api.permissions.request({origins:['https://*/*']});
      await api.runtime.sendMessage({type:'pair'});notice='';
    } else if(button.id==='enable'){
      const allowed=await api.permissions.request({origins:['https://*/*']});
      notice=allowed?'Detection enabled. Reload the login page.':'Site access declined.';
    } else {await api.runtime.sendMessage({type:button.id});notice='';}
  } catch {notice='Request unavailable. Open Desktop and try again.';}
  finally {busy=false;button.disabled=false;await refresh();}
};
async function watch(){await refresh();setTimeout(watch,500);}
void watch();
