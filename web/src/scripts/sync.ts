type Point = { x: number; y: number };

const FLIGHT_MS = 1150;
const STAGGER_MS = 160;
const SAMPLES = 24;
const PLAY_MS = 2400;

const hex = () => Math.floor(Math.random() * 0x10000).toString(16).padStart(4, '0');

const curve = (start: Point, control: Point, end: Point, t: number): Point => ({
  x: (1 - t) ** 2 * start.x + 2 * (1 - t) * t * control.x + t ** 2 * end.x,
  y: (1 - t) ** 2 * start.y + 2 * (1 - t) * t * control.y + t ** 2 * end.y,
});

export function mountSync(root: HTMLElement) {
  const devices = [...root.querySelectorAll<HTMLElement>('[data-sync-device]')];
  const template = root.querySelector<HTMLTemplateElement>('[data-sync-packet]')?.content.firstElementChild;
  const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
  if (devices.length !== 2 || !(template instanceof HTMLElement)) {
    return () => {};
  }
  const view = (device: HTMLElement) => device.querySelector('iframe')?.contentWindow;
  let turn = 0;
  let visible = false;
  let touched = false;
  let timer: number | undefined;

  const center = (device: HTMLElement): Point => {
    const origin = root.getBoundingClientRect();
    const bounds = device.getBoundingClientRect();
    return { x: bounds.left + bounds.width / 2 - origin.left, y: bounds.top + bounds.height / 2 - origin.top };
  };

  const fly = (from: HTMLElement, to: HTMLElement, delay: number) => {
    const packet = template.cloneNode(true) as HTMLElement;
    const label = packet.lastElementChild;
    if (label) label.textContent = hex();
    root.append(packet);
    const start = center(from);
    const end = center(to);
    const across = Math.abs(end.x - start.x) > Math.abs(end.y - start.y);
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
    return flight.finished.finally(() => packet.remove());
  };

  const receive = (event: MessageEvent) => {
    const from = devices.find((device) => view(device) === event.source);
    const to = devices.find((device) => device !== from);
    if (!from || !to || event.origin !== location.origin || event.data?.type !== 'factorseal:sync') {
      return;
    }
    const changes: unknown[] = event.data.changes ?? [];
    const deliver = (delivered: unknown[]) =>
      view(to)?.postMessage({ type: 'factorseal:sync', changes: delivered }, location.origin);
    if (reducedMotion.matches) {
      deliver(changes);
      return;
    }
    changes.forEach((change, index) => void fly(from, to, index * STAGGER_MS).then(() => deliver([change])));
  };

  const play = () => {
    if (devices.every((device) => device.dataset.live === 'ready')) {
      view(devices[turn])?.postMessage({ type: 'factorseal:add' }, location.origin);
      turn = 1 - turn;
    }
  };

  const schedule = () => {
    window.clearInterval(timer);
    timer = visible && !touched && !reducedMotion.matches ? window.setInterval(play, PLAY_MS) : undefined;
  };

  const touch = () => {
    touched = true;
    schedule();
  };

  const frames = devices.flatMap((device) => device.querySelector('iframe') ?? []);
  const watch = () => {
    for (const frame of frames) {
      frame.contentWindow?.addEventListener('pointerdown', touch, true);
    }
  };

  const seen = new IntersectionObserver(
    ([entry]) => {
      visible = entry.isIntersecting;
      schedule();
    },
    { threshold: 0.5 },
  );

  addEventListener('message', receive);
  frames.forEach((frame) => frame.addEventListener('load', watch));
  seen.observe(root);
  return () => {
    window.clearInterval(timer);
    seen.disconnect();
    removeEventListener('message', receive);
    frames.forEach((frame) => frame.removeEventListener('load', watch));
  };
}
