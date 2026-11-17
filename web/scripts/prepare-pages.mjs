import { mkdir, writeFile } from 'node:fs/promises';
import { createGitHubMetadataHandler } from '@cachix/site-kit/cloudflare';

const handler = createGitHubMetadataHandler({ repository: 'cachix/factorseal' });
const response = await handler({ env: { GITHUB_TOKEN: process.env.GITHUB_TOKEN } });
const metadata = await response.json();

if (metadata.stars === null && metadata.release === null) {
  throw new Error('Could not fetch GitHub metadata for the Pages deployment.');
}

const output = new URL('../dist/api/', import.meta.url);
await mkdir(output, { recursive: true });
await writeFile(new URL('github', output), JSON.stringify(metadata));
console.log('Prepared the static /api/github endpoint for Pages.');
