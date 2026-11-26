interface ThemeMessage {
  type: 'factorseal:theme';
  theme: string;
  dark: boolean;
  colors: Record<string, string>;
}

const frames = new Set<HTMLIFrameElement>();
const waiting = new Set<() => void>();
let allowed = (navigator as Navigator & { connection?: { saveData?: boolean } }).connection?.saveData !== true;
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
  const known = [...frames].some((frame) => frame.contentWindow === event.source);
  if (!known || event.origin !== location.origin || message?.type !== 'factorseal:theme') {
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

const allow = () => {
  allowed = true;
  waiting.forEach((run) => run());
};

let zoomFits: boolean | undefined;

const fit = (frame: HTMLIFrameElement) => {
  const area = frame.parentElement!;
  if (!area.clientWidth) {
    return;
  }
  const scale = Math.min(1, area.clientWidth / Number(frame.dataset.minWidth ?? 960));
  const width = area.clientWidth / scale;
  frame.style.width = `${width}px`;
  frame.style.height = `${area.clientHeight / scale}px`;
  frame.style.zoom = scale < 1 ? String(scale) : '';
  frame.style.transform = '';
  const page = frame.contentDocument?.documentElement;
  if (scale < 1 && zoomFits === undefined && page) {
    zoomFits = Math.abs(page.clientWidth - width) < 2;
  }
  if (scale < 1 && zoomFits === false) {
    frame.style.zoom = '';
    frame.style.transform = `scale(${scale})`;
  }
};

export function mountLive(root: HTMLElement) {
  const frame = root.querySelector<HTMLIFrameElement>('[data-live]');
  if (!frame?.dataset.src) {
    return () => {};
  }
  const src = frame.dataset.src;
  const retry = root.querySelector<HTMLButtonElement>('[data-live-retry]');
  const play = root.querySelector<HTMLButtonElement>('[data-live-start]');
  const receive = (event: MessageEvent) => {
    if (event.source !== frame.contentWindow) {
      return;
    }
    if (event.data === 'factorseal:error') {
      root.dataset.live = 'error';
    } else if (event.data === 'factorseal:ready') {
      root.dataset.live = 'ready';
      frames.add(frame);
      if (theme !== 'factorseal') {
        frame.contentWindow?.postMessage({ type: 'factorseal:theme', theme }, location.origin);
      }
    }
  };
  const start = () => {
    waiting.delete(start);
    delete root.dataset.live;
    frame.contentWindow?.location.replace(src);
  };
  const show = () => {
    if (allowed) {
      start();
    } else {
      waiting.add(start);
      root.dataset.live = 'idle';
    }
  };
  const stop = () => {
    waiting.delete(start);
    frames.delete(frame);
    delete root.dataset.live;
    frame.contentWindow?.location.replace('about:blank');
  };
  const restart = () => {
    stop();
    start();
  };
  const sizes = new ResizeObserver(() => fit(frame));
  const nearby = new IntersectionObserver(([entry]) => {
    if (entry.isIntersecting) {
      nearby.disconnect();
      show();
    }
  }, {
    rootMargin: '100% 0px',
  });
  addEventListener('message', receive);
  retry?.addEventListener('click', restart);
  play?.addEventListener('click', allow);
  sizes.observe(frame.parentElement!);
  nearby.observe(root);
  return () => {
    stop();
    sizes.disconnect();
    nearby.disconnect();
    removeEventListener('message', receive);
    retry?.removeEventListener('click', restart);
    play?.removeEventListener('click', allow);
  };
}
