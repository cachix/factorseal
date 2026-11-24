interface ThemeMessage {
  type: 'factorseal:theme';
  theme: string;
  dark: boolean;
  colors: Record<string, string>;
}

const frames = new Set<HTMLIFrameElement>();
let theme = 'factorseal';
let mode = document.documentElement.dataset.theme;

const post = (message: object, except?: MessageEventSource | null) => {
  for (const frame of frames) {
    if (frame.contentWindow && frame.contentWindow !== except) {
      frame.contentWindow.postMessage(message, location.origin);
    }
  }
};

const paint = ({ theme: next, dark, colors }: ThemeMessage) => {
  const root = document.documentElement;
  if (next === 'factorseal') {
    for (const name of Object.keys(colors)) {
      root.style.removeProperty(`--fs-${name}`);
    }
    return;
  }
  for (const [name, value] of Object.entries(colors)) {
    root.style.setProperty(`--fs-${name}`, value);
  }
  mode = dark ? 'dark' : 'light';
  if (root.dataset.theme !== mode) {
    root.dataset.theme = mode;
  }
};

const receive = (event: MessageEvent) => {
  const message = event.data as ThemeMessage;
  if (event.origin !== location.origin || message?.type !== 'factorseal:theme') {
    return;
  }
  paint(message);
  if (message.theme !== theme) {
    theme = message.theme;
    post({ type: 'factorseal:theme', theme }, event.source);
  }
};

new MutationObserver(() => {
  const next = document.documentElement.dataset.theme;
  if (next !== mode) {
    mode = next;
    post({ type: 'factorseal:mode', mode });
  }
}).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
addEventListener('message', receive);

const fit = (frame: HTMLIFrameElement) => {
  const area = frame.parentElement!;
  const scale = Math.min(1, area.clientWidth / Number(frame.dataset.minWidth ?? 960));
  frame.style.width = `${area.clientWidth / scale}px`;
  frame.style.height = `${area.clientHeight / scale}px`;
  frame.style.zoom = scale < 1 ? String(scale) : '';
};

export function mountLive(root: HTMLElement) {
  const frame = root.querySelector<HTMLIFrameElement>('[data-live]');
  if (!frame?.dataset.src) {
    return () => {};
  }
  const src = frame.dataset.src;
  const ready = (event: MessageEvent) => {
    if (event.source === frame.contentWindow && event.data === 'factorseal:ready') {
      root.dataset.live = 'ready';
      if (theme !== 'factorseal') {
        post({ type: 'factorseal:theme', theme });
      }
    }
  };
  const start = () => {
    frames.add(frame);
    frame.src = src;
  };
  const stop = () => {
    frames.delete(frame);
    delete root.dataset.live;
    frame.removeAttribute('src');
  };
  const sizes = new ResizeObserver(() => fit(frame));
  const nearby = new IntersectionObserver(([entry]) => (entry.isIntersecting ? start() : stop()), {
    rootMargin: '100% 0px',
  });
  addEventListener('message', ready);
  sizes.observe(frame.parentElement!);
  nearby.observe(root);
  return () => {
    stop();
    sizes.disconnect();
    nearby.disconnect();
    removeEventListener('message', ready);
  };
}
