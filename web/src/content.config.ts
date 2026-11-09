import { defineCollection } from 'astro:content';
import { docsSchema } from '@astrojs/starlight/schema';
import { blogSchema } from 'starlight-blog/schema';
import { factorsealDocsLoader } from './loaders/repo-docs';

export const collections = {
  docs: defineCollection({
    loader: factorsealDocsLoader(),
    schema: docsSchema({ extend: (context) => blogSchema(context) }),
  }),
};
