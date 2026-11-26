import {spawnSync} from 'node:child_process';
import {copyFile,mkdir,readFile,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=fileURLToPath(new URL('.',import.meta.url));
const args=process.argv.slice(2);
if(args.length>1 || (args.length===1 && args[0]!=='--store')){
  throw new Error('Usage: node extensions/browser/build.mjs [--store]');
}
const store=args[0]==='--store';
const dist=resolve(root,store?'dist/store':'dist');
const sources=[
  'core.js','background.js','content.js','labels.js','popup.html','popup.css','popup.js',
  'field.html','field.js','notice.html','notice.js','inline.css'
];
const assets={
  'mark.svg':'factorseal-mark-ink.svg',
  'icon.png':'factorseal-extension-icon-128.png'
};

for(const browser of ['firefox','chromium']){
  const out=resolve(dist,browser);
  await mkdir(out,{recursive:true});
  for(const name of sources)await copyFile(resolve(root,name),resolve(out,name));
  for(const [name,asset] of Object.entries(assets)){
    await copyFile(resolve(root,'../../assets/logo',asset),resolve(out,name));
  }
  const manifest=JSON.parse(await readFile(resolve(root,`manifest.${browser}.json`),'utf8'));
  if(store && browser==='chromium')delete manifest.key;
  await writeFile(resolve(out,'manifest.json'),JSON.stringify(manifest,null,2)+'\n');
  if(store){
    const archive=resolve(dist,`factorseal-${browser}-${manifest.version}.zip`);
    const result=spawnSync('python3',['-m','zipfile','-c',archive,'manifest.json',...sources,...Object.keys(assets)],{
      cwd:out,
      stdio:'inherit'
    });
    if(result.error)throw result.error;
    if(result.status!==0)throw new Error(`Could not package the ${browser} extension`);
  }
}
