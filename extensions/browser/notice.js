const api=globalThis.browser||globalThis.chrome;
const element=id=>document.getElementById(id);
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const send=message=>api.runtime.sendMessage({...message,document:location.hash.slice(1),frame:location.search.slice(1)}).catch(()=>null);
async function watch(){
  for(;;){
    const state=await send({type:'notice-status'});
    const text=globalThis.FactorSealLabels[state?.status]??'';
    element('status').textContent=text;
    if(!state?.active){
      if(text)await sleep(4000);
      await send({type:'notice-close'});
      return;
    }
    await sleep(400);
  }
}
async function ask(){
  while((await send({type:'notice-pending'}))?.pending)await sleep(10000);
  await send({type:'notice-close'});
}
if(location.search==='?save'){
  element('status').textContent='Save this login in FactorSeal?';
  element('choices').hidden=false;
  element('save').onclick=async()=>{if(!(await send({type:'notice-save'}))?.accepted)await send({type:'notice-close'});};
  element('later').onclick=()=>void send({type:'notice-close'});
  void ask();
} else void watch();
