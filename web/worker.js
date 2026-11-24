import {
  createGitHubMetadataHandler,
  createMarkdownMiddleware,
} from '@cachix/site-kit/cloudflare';

const githubMetadata = createGitHubMetadataHandler({ repository: 'cachix/factorseal' });
const markdown = createMarkdownMiddleware();
const desktopFile = /^\/desktop\/factorseal-desktop-[0-9a-f]+(?:_bg\.wasm|\.js)$/;
const immutable = 'public, max-age=31536000, immutable';

async function desktop(request, env) {
  const url = new URL(request.url);
  if (url.pathname.endsWith('.wasm') && /\bbr\b/.test(request.headers.get('Accept-Encoding') ?? '')) {
    const compressed = await env.ASSETS.fetch(new URL(`${url.pathname}.br`, url));
    if (compressed.ok) {
      return new Response(compressed.body, {
        headers: {
          'Cache-Control': immutable,
          'Content-Encoding': 'br',
          'Content-Type': 'application/wasm',
          Vary: 'Accept-Encoding',
        },
        encodeBody: 'manual',
      });
    }
  }
  const response = await env.ASSETS.fetch(request);
  if (!response.ok) {
    return response;
  }
  const cached = new Response(response.body, response);
  cached.headers.set('Cache-Control', immutable);
  cached.headers.set('Vary', 'Accept-Encoding');
  return cached;
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (desktopFile.test(pathname)) {
      return desktop(request, env);
    }
    if (pathname === '/api/github') {
      if (request.method !== 'GET') {
        return new Response('Method Not Allowed', {
          status: 405,
          headers: { Allow: 'GET' },
        });
      }
      return githubMetadata({ env });
    }

    return markdown({
      request,
      env,
      next: () => env.ASSETS.fetch(request),
    });
  },
};
