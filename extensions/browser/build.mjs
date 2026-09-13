import {mkdir,copyFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('.',import.meta.url));
for(const browser of ['firefox','chromium']){
  const out=`${root}dist/${browser}`;await mkdir(out,{recursive:true});
  for(const name of ['core.js','background.js','content.js','popup.html','popup.css','popup.js'])await copyFile(root+name,`${out}/${name}`);
  await copyFile(`${root}../../assets/logo/factorseal-mark-ink.svg`,`${out}/mark.svg`);
  await copyFile(`${root}../../assets/logo/factorseal-app-icon-512.png`,`${out}/icon.png`);
  await copyFile(`${root}manifest.${browser}.json`,`${out}/manifest.json`);
}
