/* Shared, dependency-free protocol primitives for Firefox and Chromium. */
(() => {
  const hex = bytes => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
  const origin = value => {
    const u = new URL(value);
    if (u.protocol !== 'https:' || u.username || u.password) throw new Error('unsupported_origin');
    return u.origin;
  };
  const decode = value => new TextDecoder('utf-8', {fatal:true}).decode(Uint8Array.from(atob(value), c => c.charCodeAt(0)));
  function validateResponse(value) {
    if (!value || typeof value !== 'object' || JSON.stringify(value).length > 65536) throw new Error('invalid_response');
    const fields = {hello:['type','version','session'],state:['type','state'],context:['type','nonce'],fill:['type','username','password'],finished:['type','reason']}[value.type];
    if (!fields || Object.keys(value).some(k => !fields.includes(k)) || fields.some(k => !(k in value))) throw new Error('invalid_response');
    for (const k of fields.filter(k => !['type','version'].includes(k))) if (typeof value[k] !== 'string') throw new Error('invalid_response');
    if (value.type === 'hello' && (value.version !== 1 || !/^[a-f0-9]{64}$/.test(value.session))) throw new Error('incompatible_version');
    if (value.type === 'context' && !/^[a-f0-9]{64}$/.test(value.nonce)) throw new Error('invalid_response');
    return value;
  }
  function browserKind(navigator,firefox=false) {
    if(firefox)return 'firefox';
    const brands=navigator?.userAgentData?.brands?.map(b=>b.brand)||[];
    const agent=navigator?.userAgent||'';
    if(brands.includes('Microsoft Edge')||/Edg\//.test(agent))return 'edge';
    if(brands.includes('Google Chrome'))return 'chrome';
    if(/Firefox\//.test(agent))return 'firefox';
    if(brands.includes('Chromium')||/Chrom(?:e|ium)\//.test(agent))return 'chromium';
    return undefined;
  }
  globalThis.FactorSealCore = {hex,origin,decode,validateResponse,browserKind};
})();
