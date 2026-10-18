const api=globalThis.browser||globalThis.chrome;
const element=id=>document.getElementById(id);
const status=element('status');
const labels=globalThis.FactorSealLabels;
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
  element('save-page').hidden=!paired||!state.detection||pending;
  element('save-page').disabled=busy||!state.site;
  element('one-time').hidden=!paired||pending;
  element('one-time').disabled=busy||!state.site;
  element('detection').hidden=!paired||state.detection;
  element('site-controls').hidden=!paired||!state.detection;
  element('pause').textContent=state.paused?'Resume on this site':'Pause on this site';
  for(const id of ['fill','pause','revoke','enable'])element(id).disabled=pending||busy||(id==='pause'&&!state.site);
  element('pairing-key').hidden=paired||!pending;
  const key=state.profile?`Profile key: ${state.profile}…`:'';
  element('profile-key').textContent=key;
  element('pending-profile-key').textContent=key;
  if(state.status!==previousStatus){notice='';previousStatus=state.status;}
  status.textContent=notice||(state.status==='connecting'&&!paired?'':labels[state.status]??state.status??'');
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
    } else {
      const result=await api.runtime.sendMessage({type:button.id});notice='';
      // The page checks itself, or offers its login, once it has focus again,
      // which the open popup keeps.
      if((button.id==='fill'&&result?.found)||(button.id==='save-page'&&result?.offered))globalThis.close();
    }
  } catch {notice='Request unavailable. Open Desktop and try again.';}
  finally {busy=false;button.disabled=false;await refresh();}
};
async function watch(){await refresh();setTimeout(watch,500);}
void watch();
