import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightBlog from 'starlight-blog';
import starlightLlmActions from 'starlight-llm-actions';
import { siteKitAstro } from '@cachix/site-kit/astro';
import { siteKitStarlight } from '@cachix/site-kit/starlight';
import { siteBlogOptions } from '@cachix/site-kit/starlight/blog';
import { siteLlmActionsOptions } from '@cachix/site-kit/starlight/llms';
import { repoDocs, repository } from './src/loaders/repo-docs.ts';

const docsGroup = (group) => repoDocs
  .filter((doc) => doc.group === group)
  .map(({ slug, label }) => (label ? { slug, label } : slug));

export default defineConfig({
  site: 'https://factorseal.dev/',
  redirects: {
    '/downloads': '/#download',
  },
  vite: {
    server: { fs: { allow: ['..'] } },
  },
  integrations: [
    siteKitAstro({ github: { repository: 'cachix/factorseal' } }),
    starlight({
      plugins: [
        siteKitStarlight(),
        starlightBlog(siteBlogOptions()),
        starlightLlmActions(siteLlmActionsOptions('FactorSeal is a hardware-backed vault for personal passwords and application secrets. Manage logins, notes, and other personal records in Desktop, or give local applications scoped access to project secrets and keyring entries. Secrets are encrypted on your device, with vault unlock protected by TPM 2.0 on Linux and Windows or Apple\'s Secure Enclave on macOS.')),
      ],
      title: 'FactorSeal',
      description: 'A hardware-backed vault for personal passwords and application secrets. Secrets are encrypted on your device and unlocked with your TPM or Secure Enclave.',
      favicon: '/favicon.svg',
      head: [
        { tag: 'meta', attrs: { name: 'theme-color', content: '#151515', media: '(prefers-color-scheme: dark)' } },
        { tag: 'meta', attrs: { name: 'theme-color', content: '#f7f3ea', media: '(prefers-color-scheme: light)' } },
      ],
      components: {
        SiteTitle: './src/overrides/SiteTitle.astro',
      },
      social: [
        { icon: 'github', label: 'GitHub', href: repository },
        { icon: 'discord', label: 'Discord', href: 'https://discord.gg/naMgvexb6q' },
      ],
      editLink: { baseUrl: `${repository}/edit/main/web/` },
      lastUpdated: true,
      customCss: ['./src/styles/custom.css'],
      sidebar: [
        {
          label: 'Getting Started',
          items: docsGroup('start'),
        },
        {
          label: 'Apps',
          items: docsGroup('apps'),
        },
        {
          label: 'Reference',
          items: docsGroup('reference'),
        },
      ],
    }),
  ],
});
