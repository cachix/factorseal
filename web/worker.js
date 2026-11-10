import {
  createGitHubMetadataHandler,
  createMarkdownMiddleware,
} from '@cachix/site-kit/cloudflare';

const githubMetadata = createGitHubMetadataHandler({ repository: 'cachix/factorseal' });
const markdown = createMarkdownMiddleware();

export default {
  async fetch(request, env) {
    if (new URL(request.url).pathname === '/api/github') {
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
