(() => {
  if (globalThis.__factorsealContent) return;
  globalThis.__factorsealContent=true;
  const api=globalThis.browser||globalThis.chrome;
  const documentId=crypto.randomUUID();
  const buttons=new Map(), hosts=new WeakMap();
  let selected, enabled=null, scheduled, placing, notice, filled;
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
    return document.elementsFromPoint(x,y).find(element=>!hosts.has(element))===input;
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
  const important=(host,values)=>{for(const [name,value] of Object.entries(values))host.style.setProperty(name,value,'important');};
  function frame(page,name) {
    const host=document.createElement('div');
    important(host,{all:'initial',position:'fixed','z-index':'2147483647',display:'block'});
    const view=document.createElement('iframe');
    view.src=`${api.runtime.getURL(page)}?${name}#${documentId}`;
    view.style.cssText='all:initial;display:block;width:100%;height:100%;border:0;color-scheme:normal;pointer-events:inherit';
    host.attachShadow({mode:'closed'}).append(view);
    hosts.set(host,{name,size:[0,0]});
    document.documentElement.append(host);
    return host;
  }
  function place() {
    placing=false;
    const inputs=enabled&&selected?[selected.username,selected.password]:[];
    for(const [input,host] of buttons)if(!inputs.includes(input)){host.remove();buttons.delete(input);}
    for(const input of inputs){
      if(!buttons.has(input))buttons.set(input,frame('field.html',crypto.randomUUID()));
      const host=buttons.get(input), r=input.getBoundingClientRect(), side=Math.max(16,Math.min(24,r.height-8));
      important(host,{left:`${r.right-side-6}px`,top:`${r.top+(r.height-side)/2}px`,width:`${side}px`,height:`${side}px`,display:visible(input)?'block':'none'});
      hosts.get(host).size=[side,side];
    }
  }
  const reposition=()=>{if(!placing && buttons.size){placing=true;requestAnimationFrame(place);}};
  function showNotice(mode) {
    notice?.remove();
    notice=frame('notice.html',mode);
    const height=mode==='save'?112:96;
    important(notice,{top:'16px',right:'16px',width:'360px','max-width':'calc(100% - 32px)',height:`${height}px`,'pointer-events':mode==='save'?'auto':'none'});
    hosts.get(notice).size=[360,height];
  }
  function untouched(host) {
    const look=getComputedStyle(host), r=host.getBoundingClientRect(), [width,height]=hosts.get(host).size;
    const top=document.elementsFromPoint(r.left+r.width/2,r.top+r.height/2).find(element=>element===host || !hosts.has(element));
    return look.opacity==='1' && look.visibility==='visible' && look.filter==='none' && look.clipPath==='none'
      && r.width>0 && r.width<=width+1 && r.height<=height+1 && top===host;
  }
  async function detect() {
    scheduled=false;
    if(selected && !valid()) {
      selected=null;
      try {await api.runtime.sendMessage({type:'invalidated',document:documentId});}catch{}
    }
    selected=selected||form();
    if(selected && enabled===null)enabled=(await api.runtime.sendMessage({type:'field',document:documentId}).catch(()=>null))?.show===true;
    place();
  }
  const schedule=()=>{if(!scheduled){scheduled=true;setTimeout(()=>void detect(),300);}};
  let submitted=false;
  function offerSave(owner,automatic){
    if(submitted || location.protocol!=='https:' || window.top!==window)return false;
    if(!owner?.querySelectorAll || new URL(owner.action||location.href,location.href).origin!==location.origin)return false;
    const inputs=[...owner.querySelectorAll('input')].filter(visible);
    const passwords=inputs.filter(i=>i.type==='password');
    const fresh=passwords.filter(i=>i.autocomplete==='new-password');
    const chosen=fresh.length?fresh:passwords;
    if(chosen.length<1 || chosen.length>2 || chosen.some(i=>!i.value || i.value!==chosen[0].value))return false;
    const names=inputs.filter(i=>['text','email'].includes(i.type));
    const preferred=names.filter(i=>i.autocomplete==='username');
    const username=preferred.length===1?preferred[0]:names.length===1?names[0]:null;
    if(!username?.value || new TextEncoder().encode(username.value).length>512 || new TextEncoder().encode(chosen[0].value).length>4096)return false;
    submitted=true;
    if(automatic && filled?.username===username.value && filled.password===chosen[0].value)return false;
    // Only capture an intentional submission. Never persist form values.
    void api.runtime.sendMessage({type:'save',document:documentId,username:username.value,password:chosen[0].value})
      .then(result=>{if(result?.ask)showNotice('save');}).catch(()=>{});
    return true;
  }
  document.addEventListener('submit',event=>{if(event.isTrusted)offerSave(event.target,true);},true);
  document.addEventListener('input',event=>{if(event.isTrusted)submitted=false;},true);
  const foreign=record=>!hosts.has(record.target) && (record.type!=='childList' || [...record.addedNodes,...record.removedNodes].some(node=>!hosts.has(node)));
  new MutationObserver(records=>{if(records.some(foreign))schedule();}).observe(document.documentElement,{subtree:true,childList:true,attributes:true,attributeFilter:['type','style','class','disabled','readonly','action']});
  document.addEventListener('visibilitychange',schedule);window.addEventListener('focus',schedule);schedule();
  addEventListener('scroll',reposition,{capture:true,passive:true});addEventListener('resize',reposition,{passive:true});
  const askPending=()=>void api.runtime.sendMessage({type:'pending',document:documentId}).then(result=>{if(result?.save && !notice)showNotice('save');}).catch(()=>{});
  askPending();
  api.runtime.onMessage.addListener((message,sender,reply)=>{
    if(sender.id!==api.runtime.id)return;
    if(message.type==='save-current'){
      const forms=[...new Set([...document.querySelectorAll('input[type="password"]')].filter(visible).map(i=>i.form).filter(Boolean))];
      submitted=false;
      reply({offered:forms.length===1 && offerSave(forms[0])});return;
    }
    if(message.type==='owns'){reply({valid:message.document===documentId});return;}
    if(message.type==='pressed'){
      const host=message.page==='notice'?notice:[...buttons.values()].find(host=>hosts.get(host).name===message.frame);
      reply({valid:message.document===documentId && !!host && hosts.get(host).name===message.frame && (message.page!=='field' || valid()) && untouched(host)});return;
    }
    if(message.type==='find'){if(!valid())selected=form();reply({document:selected?documentId:null});place();return;}
    if(message.type==='site-changed'){enabled=null;selected=null;schedule();reply({});return;}
    if(message.type==='notice'){showNotice('status');reply({});return;}
    if(message.type==='close-notice'){notice?.remove();notice=null;askPending();reply({});return;}
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
      filled={username:message.username,password:message.password};
      reply({filled:true});
    }
  });
})();
