const api=globalThis.browser||globalThis.chrome;
document.getElementById('fill').onclick=()=>void api.runtime.sendMessage({type:'fill-field',document:location.hash.slice(1),frame:location.search.slice(1)}).catch(()=>{});
