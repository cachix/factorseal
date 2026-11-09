const RELEASING_MS = 700;
const DENIED_MS = 4000;
const TYPE_MS = 28;

export function mountBrowser(root: HTMLElement) {
  let timer: number | undefined;
  const inputs = [...root.querySelectorAll<HTMLElement>('[data-username], [data-password]')];
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  const step = (value: string) => {
    window.clearTimeout(timer);
    root.dataset.step = value;
  };

  const clear = () => {
    delete root.dataset.filled;
    for (const input of inputs) input.textContent = '';
  };

  const type = (queue: { input: HTMLElement; text: string }[]) => {
    const [current, ...rest] = queue;
    if (!current) {
      root.dataset.filled = '';
      step('idle');
      return;
    }
    current.input.textContent = current.text.slice(0, current.input.textContent!.length + 1);
    const done = current.input.textContent === current.text;
    timer = window.setTimeout(() => type(done ? rest : queue), TYPE_MS);
  };

  const fill = () => {
    if (reducedMotion.matches) {
      for (const input of inputs) input.textContent = input.dataset.value ?? '';
      root.dataset.filled = '';
      step('idle');
      return;
    }
    step('filling');
    type(inputs.map((input) => ({ input, text: input.dataset.value ?? '' })));
  };

  root.addEventListener('click', (event) => {
    const target = event.target as Element;
    const current = root.dataset.step;
    if (target.closest('[data-extension]')) {
      root.dataset.popup = root.dataset.popup === 'open' ? 'closed' : 'open';
    } else if (target.closest('[data-fill]') && (current === 'idle' || current === 'denied')) {
      root.dataset.popup = 'closed';
      clear();
      step('approval');
    } else if (target.closest('[data-account]') && current === 'approval') {
      step('releasing');
      timer = window.setTimeout(fill, RELEASING_MS);
    } else if (target.closest('[data-deny]') && current === 'approval') {
      step('denied');
      timer = window.setTimeout(() => step('idle'), DENIED_MS);
    } else if (target.closest('[data-cancel]') && current === 'approval') {
      step('idle');
    }
  });
}
