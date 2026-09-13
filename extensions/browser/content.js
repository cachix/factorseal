(() => {
  if (globalThis.__factorsealContent) return;
  globalThis.__factorsealContent=true;
  const api=globalThis.browser||globalThis.chrome;
  const documentId=crypto.randomUUID();
  let attempted=false, selected, scheduled;
  const visible=input=>{
    if(!(input instanceof HTMLInputElement) || input.disabled || input.readOnly || !input.getClientRects().length)return false;
    for(let parent=input;parent;parent=parent.parentElement){
      const style=getComputedStyle(parent);
      if(style.visibility!=='visible' || style.display==='none' || style.opacity==='0')return false;
    }
    const r=input.getBoundingClientRect();
    if(r.width<8 || r.height<8 || r.right<=0 || r.bottom<=0 || r.left>=innerWidth || r.top>=innerHeight)return false;
    const x=(Math.max(0,r.left)+Math.min(innerWidth,r.right))/2;
    const y=(Math.max(0,r.top)+Math.min(innerHeight,r.bottom))/2;
    return document.elementFromPoint(x,y)===input;
  };
  function form() {
    if(location.protocol!=='https:' || window.top!==window)return null;
    const passwords=[...document.querySelectorAll('input[type="password"]')].filter(visible);
    // Ambiguous signup/change-password forms require a later explicit selector UI.
    if(passwords.length!==1)return null;
    const password=passwords[0], owner=password.form;
    if (!owner || new URL(owner.action||location.href,location.href).origin!==location.origin)return null;
    const usernames=[...owner.querySelectorAll('input')].filter(i=>visible(i) && ['text','email'].includes(i.type));
    const preferred=usernames.filter(i=>i.autocomplete==='username');
    const username=preferred.length===1?preferred[0]:usernames.length===1?usernames[0]:null;
    if(!username || password.autocomplete==='new-password')return null;
    return {username,password,owner,origin:location.origin};
  }
  function valid() {
    const current=form();
    return !!selected && !!current && current.username===selected.username && current.password===selected.password && current.owner===selected.owner && current.origin===selected.origin;
  }
  async function detect() {
    scheduled=false;
    if(attempted && selected && !valid()) {
      selected=null;
      try {await api.runtime.sendMessage({type:'invalidated',document:documentId});}catch{}
      return;
    }
    if(attempted || document.visibilityState!=='visible')return;
    selected=form();if(!selected)return;
    attempted=true;
    try {const r=await api.runtime.sendMessage({type:'detected',document:documentId});if(!r?.accepted)attempted=false;}catch{}
  }
  const schedule=()=>{if(!scheduled){scheduled=true;setTimeout(()=>void detect(),300);}};
  new MutationObserver(schedule).observe(document.documentElement,{subtree:true,childList:true,attributes:true,attributeFilter:['type','style','class','disabled','readonly','action']});
  document.addEventListener('visibilitychange',schedule);window.addEventListener('focus',schedule);schedule();
  api.runtime.onMessage.addListener((message,sender,reply)=>{
    if(sender.id!==api.runtime.id)return;
    if(message.type==='retry'){attempted=false;schedule();reply({ok:true});return;}
    const ok=message.document===documentId && valid();
    if(message.type==='check'){reply({valid:ok,document:documentId});return;}
    if(message.type==='fill') {
      if(!ok || typeof message.username!=='string' || typeof message.password!=='string' || message.username.length>4096 || message.password.length>4096){reply({filled:false});return;}
      const set=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
      set.call(selected.username,message.username);
      selected.username.dispatchEvent(new Event('input',{bubbles:true}));
      // Page event handlers may replace the form synchronously after username input.
      if(!valid()){reply({filled:false});return;}
      set.call(selected.password,message.password);
      selected.password.dispatchEvent(new Event('input',{bubbles:true}));
      reply({filled:true});
    }
  });
})();
