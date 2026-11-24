const SITE = 'https://github.com';
const PAIR = 'Pair browser profile';
const REVOKE = 'Disconnect browser profile';
const PROFILE = '3f9a1c07b2e4d685';
const PASSWORD = '•'.repeat(16);
const TYPE_MS = 28;

interface Extension {
  runtime: { sendMessage(message: { type: string }): Promise<object> };
  permissions: { request(): Promise<boolean> };
}

declare global {
  interface Window {
    factorsealExtension?: Extension;
  }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export function mountBrowser(root: HTMLElement) {
  const frame = root.querySelector<HTMLIFrameElement>('[data-live]');
  const popup = root.querySelector<HTMLIFrameElement>('.browser-popup');
  const toggle = root.querySelector<HTMLButtonElement>('[data-extension]');
  const username = root.querySelector<HTMLElement>('[data-username]');
  const password = root.querySelector<HTMLElement>('[data-password]');
  if (!frame || !popup || !toggle || !username || !password) {
    return () => {};
  }
  const state = { paired: true, detection: true, site: true, paused: false, pending: false, status: '', profile: PROFILE };
  let request = '';
  let mounted = true;

  const show = () => root.toggleAttribute('data-paused', state.paused || !state.paired);

  const open = () => {
    popup.srcdoc = popup.dataset.popup ?? '';
    root.dataset.open = '';
    toggle.setAttribute('aria-expanded', 'true');
  };

  const close = () => {
    popup.removeAttribute('srcdoc');
    delete root.dataset.open;
    toggle.setAttribute('aria-expanded', 'false');
  };

  const ask = (site: string) => {
    if (root.dataset.live !== 'ready') {
      state.status = 'desktop_unavailable';
      return false;
    }
    request = site;
    state.pending = true;
    state.status = 'awaiting_approval';
    root.dataset.prompt = '';
    frame.contentWindow?.postMessage({ type: 'factorseal:fill', site }, location.origin);
    return true;
  };

  const settle = () => {
    request = '';
    state.pending = false;
    delete root.dataset.prompt;
    delete root.dataset.live;
    frame.contentWindow?.location.reload();
    show();
  };

  const fill = async (name: string) => {
    delete root.dataset.filled;
    username.textContent = '';
    password.textContent = '';
    for (const [target, text] of [
      [username, name],
      [password, PASSWORD],
    ] as const) {
      for (const character of text) {
        if (!mounted) return;
        target.textContent += character;
        await sleep(TYPE_MS);
      }
    }
    root.dataset.filled = '';
  };

  const receive = (event: MessageEvent) => {
    if (event.source !== frame.contentWindow || event.data?.type !== 'factorseal:browser') {
      return;
    }
    const { approved, username: name } = event.data;
    if (request === PAIR) {
      state.paired = approved;
    } else if (request === REVOKE) {
      state.paired &&= !approved;
    } else if (approved && name) {
      void fill(name);
    }
    state.status = !approved ? 'denied' : request === REVOKE ? 'revoked' : '';
    settle();
  };

  const messages: Record<string, () => object> = {
    status: () => ({ ...state }),
    fill: () => {
      if (!state.paired) {
        state.status = 'pair_required';
        return { found: false };
      }
      if (state.pending) {
        state.status = 'busy';
        return { found: false };
      }
      const found = ask(SITE);
      if (found) close();
      return { found };
    },
    pair: () => (ask(PAIR), {}),
    revoke: () => (ask(REVOKE), {}),
    cancel: () => {
      frame.contentWindow?.postMessage({ type: 'factorseal:cancel' }, location.origin);
      state.status = 'cancelled';
      settle();
      return {};
    },
    pause: () => {
      state.paused = !state.paused;
      show();
      return {};
    },
    'save-page': () => {
      state.status = 'already_saved';
      return { offered: false };
    },
    'one-time': () => {
      state.status = 'no_code';
      return {};
    },
  };
  messages['fill-field'] = messages.fill;

  window.factorsealExtension = {
    runtime: { sendMessage: async ({ type }) => messages[type]?.() ?? {} },
    permissions: { request: async () => true },
  };

  const fit = () => {
    const body = popup.contentDocument?.body;
    const view = popup.contentWindow as (Window & typeof globalThis) | null;
    if (body && view) {
      new view.ResizeObserver(() => (popup.style.height = `${body.scrollHeight}px`)).observe(body);
    }
  };

  const outside = (event: PointerEvent) => {
    if (root.dataset.open !== undefined && !toggle.contains(event.target as Node)) close();
  };

  for (const field of root.querySelectorAll<HTMLIFrameElement>('[data-field]')) {
    field.srcdoc = field.dataset.field ?? '';
  }
  toggle.onclick = () => (root.dataset.open === undefined ? open() : close());
  popup.addEventListener('load', fit);
  addEventListener('message', receive);
  document.addEventListener('pointerdown', outside);
  return () => {
    mounted = false;
    delete window.factorsealExtension;
    popup.removeEventListener('load', fit);
    removeEventListener('message', receive);
    document.removeEventListener('pointerdown', outside);
  };
}
