import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { docsLoader } from '@astrojs/starlight/loaders';
import type { Loader, LoaderContext } from 'astro/loaders';

interface RepoDoc {
  slug: string;
  file: string;
  group: 'start' | 'apps' | 'reference';
  label?: string;
  title?: string;
}

export const repository = 'https://github.com/cachix/factorseal';

export const repoDocs: RepoDoc[] = [
  { slug: 'overview', file: 'README.md', group: 'start', title: 'Overview' },
  { slug: 'usage', file: 'docs/usage.md', group: 'start', label: 'Usage guide' },
  { slug: 'desktop', file: 'factorseal-desktop/README.md', group: 'apps', label: 'Desktop' },
  { slug: 'mobile', file: 'factorseal-mobile/README.md', group: 'apps', label: 'Android and iOS' },
  { slug: 'browser-extension', file: 'extensions/browser/README.md', group: 'apps', label: 'Browser extension' },
  { slug: 'security', file: 'SECURITY.md', group: 'reference' },
  { slug: 'architecture', file: 'docs/architecture.md', group: 'reference', label: 'Architecture' },
  { slug: 'browser-integration', file: 'docs/browser-integration.md', group: 'reference', label: 'Browser integration' },
  { slug: 'packaging', file: 'packaging/README.md', group: 'reference' },
  { slug: 'development', file: 'docs/development.md', group: 'reference', label: 'Development' },
];

const root = fileURLToPath(new URL('../../../', import.meta.url));
const slugs = new Map(repoDocs.map(({ file, slug }) => [file, slug]));
const alerts: Record<string, string> = {
  NOTE: 'note',
  TIP: 'tip',
  IMPORTANT: 'note',
  WARNING: 'caution',
  CAUTION: 'danger',
};

function isHeader(line: string, inHtml: boolean) {
  const text = line.trim();
  return text === '' || inHtml || text.startsWith('<') || text.startsWith('# ') || /^\[Back to .+\]\(.+\)\.?$/.test(text);
}

function stripHeader(lines: string[]) {
  let title: string | undefined;
  let inHtml = false;
  let index = 0;
  for (; index < lines.length && isHeader(lines[index], inHtml); index += 1) {
    const text = lines[index].trim();
    if (text.startsWith('# ')) title ??= text.slice(2).trim();
    if (text.startsWith('<')) inHtml = true;
    if (text === '') inHtml = false;
  }
  return { title, lines: lines.slice(index) };
}

function asides(markdown: string) {
  return markdown.replace(/^> \[!(\w+)\]\n((?:>.*\n?)+)/gm, (_, kind: string, quote: string) => {
    const body = quote.replace(/^> ?/gm, '').trimEnd();
    return `:::${alerts[kind] ?? 'note'}\n${body}\n:::\n`;
  });
}

function links(markdown: string, file: string) {
  return markdown.replace(/(!?)\]\(([^)\s]+)\)/g, (match, image: string, target: string) => {
    if (/^(?:[a-z]+:|#)/i.test(target)) return match;
    const [location, anchor] = target.split('#');
    const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(file), location));
    const slug = slugs.get(resolved);
    const hash = anchor ? `#${anchor}` : '';
    if (slug && !image) return `${image}](/${slug}/${hash})`;
    const kind = image ? 'raw' : 'blob';
    return `${image}](${repository}/${kind}/main/${resolved}${hash})`;
  });
}

export function siteMarkdown(source: string, file: string) {
  const { title, lines } = stripHeader(source.split('\n'));
  return { title, body: links(asides(lines.join('\n')), file) };
}

async function lastCommit(file: string) {
  try {
    const { stdout } = await promisify(execFile)('git', ['log', '-1', '--format=%cI', '--', file], { cwd: root });
    return stdout.trim() ? new Date(stdout.trim()) : undefined;
  } catch {
    return undefined;
  }
}

async function loadDoc(context: LoaderContext, doc: RepoDoc) {
  const file = path.join(root, doc.file);
  const source = await readFile(file, 'utf8');
  const { title, body } = siteMarkdown(source, doc.file);
  const lastUpdated = await lastCommit(file);
  const data = await context.parseData({ id: doc.slug, data: { title: doc.title ?? title, ...(lastUpdated && { lastUpdated }) } });
  context.store.set({
    id: doc.slug,
    data,
    body,
    filePath: path.relative(fileURLToPath(context.config.root), file),
    digest: context.generateDigest(source),
    rendered: await context.renderMarkdown(body, { fileURL: new URL(`src/content/docs/${doc.slug}.md`, context.config.root) }),
  });
}

export function factorsealDocsLoader(): Loader {
  const docs = docsLoader();
  return {
    name: 'factorseal-docs',
    async load(context) {
      await docs.load(context);
      await Promise.all(repoDocs.map((doc) => loadDoc(context, doc)));
      const byPath = new Map(repoDocs.map((doc) => [path.join(root, doc.file), doc]));
      for (const file of byPath.keys()) context.watcher?.add(file);
      context.watcher?.on('change', (changed) => {
        const doc = byPath.get(changed);
        if (doc) loadDoc(context, doc).catch((error) => context.logger.error(String(error)));
      });
    },
  };
}
