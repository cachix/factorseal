import { createAstroMotionLifecycle } from '@cachix/site-kit/motion';

type Side = 'desktop' | 'phone';
type Point = { x: number; y: number };

const FLIGHT_MS = 1150;
const STAGGER_MS = 160;
const BATCH_MS = 450;
const FRESH_MS = 1600;
const IDLE_MS = 9000;
const SAMPLES = 24;

const other = (side: Side): Side => (side === 'desktop' ? 'phone' : 'desktop');
const hex = () => Math.floor(Math.random() * 0x10000).toString(16).padStart(4, '0');
const clamp = (value: number, min: number, max: number) => Math.min(Math.max(value, min), max);

const curve = (start: Point, control: Point, end: Point, t: number): Point => ({
  x: (1 - t) ** 2 * start.x + 2 * (1 - t) * t * control.x + t ** 2 * end.x,
  y: (1 - t) ** 2 * start.y + 2 * (1 - t) * t * control.y + t ** 2 * end.y,
});

export function mountSync(root: HTMLElement) {
  const stage = root.querySelector<HTMLElement>('.sync-stage');
  const desktop = root.querySelector<HTMLElement>('.sync-desktop');
  const phone = root.querySelector<HTMLElement>('[data-sync-phone]');
  const lane = root.querySelector<HTMLElement>('[data-sync-lane]');
  const capsule = root.querySelector<HTMLTemplateElement>('[data-sync-capsule]');
  const wifi = root.querySelector<HTMLButtonElement>('[data-sync-wifi]');
  const count = root.querySelector<HTMLElement>('.fs-nav__item[aria-current] .fs-count');
  const template = capsule?.content.firstElementChild;
  if (!stage || !desktop || !phone || !lane || !(template instanceof HTMLElement) || !wifi || !count) return;

  const scopes: Record<Side, HTMLElement> = { desktop, phone };
  const entries = (root.dataset.entries ?? '').split(' ').filter(Boolean);
  const vaults: Record<Side, string[]> = { desktop: [], phone: [] };
  const arriving: Record<Side, Set<string>> = { desktop: new Set(), phone: new Set() };
  const pending: Record<Side, boolean> = { desktop: false, phone: false };
  const batches: Partial<Record<Side, number>> = {};
  let online = true;
  let reducedMotion = false;
  let active = false;
  let autoplay = true;
  let generation = 0;
  let step = 0;
  let timer: number | undefined;
  let idle: number | undefined;

  const render = (side: Side, ids: string[]) => {
    for (const slot of scopes[side].querySelectorAll<HTMLElement>('[data-entry]')) {
      const id = slot.dataset.entry ?? '';
      const shown = ids.includes(id);
      if (shown && !vaults[side].includes(id)) {
        slot.setAttribute('data-fresh', '');
        window.setTimeout(() => slot.removeAttribute('data-fresh'), FRESH_MS);
      }
      slot.toggleAttribute('data-shown', shown);
    }
    vaults[side] = ids;
    if (side === 'desktop') count.textContent = String(ids.length);
  };

  const merge = (side: Side, ids: string[]) => {
    render(side, entries.filter((id) => vaults[side].includes(id) || ids.includes(id)));
  };

  const rowCenter = (side: Side, id: string): Point => {
    const slot = scopes[side].querySelector<HTMLElement>(`[data-entry="${id}"]`);
    const list = scopes[side].querySelector<HTMLElement>('.fs-rows, .phone__screen');
    if (!slot || !list) return { x: 0, y: 0 };
    const origin = stage.getBoundingClientRect();
    const bounds = list.getBoundingClientRect();
    const row = slot.getBoundingClientRect();
    const height = slot.firstElementChild?.scrollHeight ?? 0;
    return {
      x: bounds.left + bounds.width / 2 - origin.left,
      y: clamp(row.top + height / 2, bounds.top + height / 2, bounds.bottom - height / 2) - origin.top,
    };
  };

  const fly = (from: Side, id: string, delay: number) => {
    const to = other(from);
    const sent = generation;
    arriving[to].add(id);
    const land = () => {
      arriving[to].delete(id);
      if (sent === generation) merge(to, [id]);
    };
    if (reducedMotion) {
      land();
      return;
    }
    const packet = template.cloneNode(true) as HTMLElement;
    const label = packet.lastElementChild;
    if (label) label.textContent = hex();
    stage.append(packet);
    const start = rowCenter(from, id);
    const end = rowCenter(to, id);
    const across = getComputedStyle(lane).getPropertyValue('--sync-axis').trim() !== 'y';
    const control = across
      ? { x: (start.x + end.x) / 2, y: Math.min(start.y, end.y) - Math.abs(end.x - start.x) * 0.28 }
      : { x: Math.max(start.x, end.x) + Math.abs(end.y - start.y) * 0.3, y: (start.y + end.y) / 2 };
    const { offsetWidth: width, offsetHeight: height } = packet;
    const frames = Array.from({ length: SAMPLES + 1 }, (_, index) => {
      const t = index / SAMPLES;
      const { x, y } = curve(start, control, end, t);
      const scale = 0.7 + 0.3 * Math.sin(Math.PI * Math.min(1, t * 1.15));
      return {
        offset: t,
        opacity: t < 0.1 ? t / 0.1 : t > 0.9 ? (1 - t) / 0.1 : 1,
        transform: `translate(${x - width / 2}px, ${y - height / 2}px) scale(${scale})`,
      };
    });
    const flight = packet.animate(frames, { delay, duration: FLIGHT_MS, easing: 'cubic-bezier(0.5, 0, 0.2, 1)', fill: 'backwards' });
    flight.finished.then(() => {
      packet.remove();
      land();
    });
  };

  const flush = (side: Side) => {
    window.clearTimeout(batches[side]);
    batches[side] = undefined;
    if (!online || !pending[side]) return;
    pending[side] = false;
    const to = other(side);
    vaults[side]
      .filter((id) => !vaults[to].includes(id) && !arriving[to].has(id))
      .forEach((id, index) => fly(side, id, index * STAGGER_MS));
  };

  const queue = (side: Side) => {
    pending[side] = true;
    if (online && batches[side] === undefined) batches[side] = window.setTimeout(() => flush(side), BATCH_MS);
  };

  const add = (side: Side, ids: string[]) => {
    merge(side, ids);
    queue(side);
  };

  const connect = (value: boolean) => {
    online = value;
    root.toggleAttribute('data-online', online);
    wifi.setAttribute('aria-pressed', String(online));
    if (online) {
      flush('desktop');
      flush('phone');
    }
  };

  const clear = () => {
    generation += 1;
    for (const side of ['desktop', 'phone'] as const) {
      window.clearTimeout(batches[side]);
      batches[side] = undefined;
      pending[side] = false;
      arriving[side].clear();
      render(side, []);
    }
    for (const packet of stage.querySelectorAll('.sync-packet')) packet.remove();
    connect(true);
  };

  const steps: [number, () => void][] = [
    [700, () => add('desktop', ['fastmail'])],
    [1500, () => add('phone', ['github'])],
    [1500, () => add('desktop', ['figma', 'hetzner'])],
    [1900, () => connect(false)],
    [700, () => add('phone', ['wifi'])],
    [900, () => add('desktop', ['identity'])],
    [800, () => add('phone', ['tailscale'])],
    [1300, () => connect(true)],
    [2000, () => add('phone', ['visa'])],
    [3600, clear],
  ];

  const stop = () => {
    window.clearTimeout(timer);
    timer = undefined;
  };

  const schedule = () => {
    stop();
    if (!active || !autoplay || reducedMotion) return;
    const [delay, run] = steps[step];
    timer = window.setTimeout(() => {
      run();
      step = (step + 1) % steps.length;
      schedule();
    }, delay);
  };

  const interact = () => {
    autoplay = false;
    stop();
    window.clearTimeout(idle);
    idle = window.setTimeout(() => {
      clear();
      autoplay = true;
      step = 0;
      schedule();
    }, IDLE_MS);
  };

  for (const button of root.querySelectorAll<HTMLButtonElement>('[data-sync-add]')) {
    button.addEventListener('click', () => {
      interact();
      const side = button.dataset.syncAdd === 'phone' ? 'phone' : 'desktop';
      const entry = entries.find((id) => !vaults.desktop.includes(id) && !vaults.phone.includes(id));
      if (entry) add(side, [entry]);
      else clear();
    });
  }
  wifi.addEventListener('click', () => {
    interact();
    connect(!online);
  });

  createAstroMotionLifecycle({
    target: root,
    threshold: 0.25,
    onChange: (visible, state) => {
      active = visible;
      reducedMotion = state.reducedMotion;
      if (reducedMotion && vaults.desktop.length === 0) {
        render('desktop', entries);
        render('phone', entries);
      }
      schedule();
    },
  });
}
