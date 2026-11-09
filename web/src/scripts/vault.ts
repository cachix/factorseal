import { mountTotp } from './totp';
import { unlockArt } from './unlock-art';

const TYPING_MS = 520;
const UNLOCK_STEP_MS = 900;
const COPIED_MS = 2000;
const PASSWORD = '•'.repeat(14);

export function mountVault(root: HTMLElement) {
  const canvas = root.querySelector<HTMLCanvasElement>('[data-unlock-art]');
  const art = canvas ? unlockArt(canvas) : undefined;
  const password = root.querySelector<HTMLElement>('[data-password] span');
  const placeholder = password?.textContent ?? '';
  const step = root.querySelector<HTMLElement>('[data-unlock-step]');
  const [sealedLine, ...unlockLines]: string[] = JSON.parse(root.dataset.unlockSteps ?? '[]');
  const timers = new Set<number>();

  const later = (callback: () => void, delay: number) => {
    const timer = window.setTimeout(() => {
      timers.delete(timer);
      callback();
    }, delay);
    timers.add(timer);
  };

  const conceal = () => {
    for (const field of root.querySelectorAll<HTMLElement>('[data-field][data-revealed]')) {
      field.removeAttribute('data-revealed');
      const value = field.querySelector<HTMLElement>('[data-concealed]');
      if (value) value.textContent = '•'.repeat(value.dataset.value?.length ?? 0);
    }
  };

  const showPage = (page: string) => {
    root.dataset.page = page;
    for (const view of root.querySelectorAll<HTMLElement>('[data-view]')) view.hidden = view.dataset.view !== page;
    for (const target of root.querySelectorAll<HTMLElement>('[data-state-target]')) {
      if (target.dataset.stateTarget === page) target.setAttribute('aria-current', 'page');
      else target.removeAttribute('aria-current');
    }
  };

  const selectItem = (row: HTMLElement) => {
    const view = row.closest<HTMLElement>('[data-view]')?.dataset.view;
    const id = row.dataset.item;
    if (!view || !id) return;
    conceal();
    for (const other of root.querySelectorAll<HTMLElement>(`[data-view="${view}"] [data-item]`)) {
      other.setAttribute('aria-selected', String(other === row));
    }
    for (const panel of root.querySelectorAll<HTMLElement>(`[data-view="${view}"] [data-panel]`)) {
      panel.toggleAttribute('data-active', panel.dataset.panel === id);
    }
  };

  const reveal = (field: HTMLElement) => {
    const value = field.querySelector<HTMLElement>('[data-concealed]');
    if (!value) return;
    const shown = field.toggleAttribute('data-revealed');
    value.textContent = shown ? value.dataset.value ?? '' : '•'.repeat(value.dataset.value?.length ?? 0);
  };

  const copy = (field: HTMLElement) => {
    for (const other of root.querySelectorAll('[data-field][data-copied]')) other.removeAttribute('data-copied');
    field.setAttribute('data-copied', '');
    later(() => field.removeAttribute('data-copied'), COPIED_MS);
  };

  const seal = () => {
    conceal();
    root.dataset.state = 'sealed';
  };

  const unlock = () => {
    if (root.dataset.state !== 'sealed') return;
    root.dataset.state = 'typing';
    if (password) password.textContent = PASSWORD;
    later(() => {
      root.dataset.state = 'unlocking';
      art?.start();
      unlockLines.forEach((line, index) => later(() => {
        if (step) step.textContent = line;
      }, index * UNLOCK_STEP_MS));
      later(() => {
        art?.stop();
        if (password) password.textContent = placeholder;
        if (step) step.textContent = sealedLine ?? '';
        root.dataset.state = 'unsealed';
      }, unlockLines.length * UNLOCK_STEP_MS);
    }, TYPING_MS);
  };

  root.addEventListener('click', (event) => {
    const target = event.target as Element;
    const page = target.closest<HTMLElement>('[data-state-target]');
    const row = target.closest<HTMLElement>('[data-item]');
    const field = target.closest<HTMLElement>('[data-field]');
    if (page?.dataset.stateTarget) showPage(page.dataset.stateTarget);
    else if (row) selectItem(row);
    else if (field && target.closest('[data-reveal]')) reveal(field);
    else if (field && target.closest('[data-copy]')) copy(field);
    else if (target.closest('[data-seal]')) seal();
    else if (target.closest('[data-unlock]')) unlock();
  });

  mountTotp(root);
}
