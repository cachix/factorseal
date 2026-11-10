import { createAstroMotionLifecycle } from '@cachix/site-kit/motion';

const PERIOD = 30;

function base32(secret: string) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const character of secret.replace(/=+$/, '').toUpperCase()) {
    bits += alphabet.indexOf(character).toString(2).padStart(5, '0');
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  bytes.forEach((_, index) => {
    bytes[index] = Number.parseInt(bits.slice(index * 8, index * 8 + 8), 2);
  });
  return bytes;
}

export async function totp(secret: string, now = Date.now()) {
  const counter = new DataView(new ArrayBuffer(8));
  counter.setBigUint64(0, BigInt(Math.floor(now / 1000 / PERIOD)));
  const key = await crypto.subtle.importKey('raw', base32(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter.buffer));
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(binary % 1_000_000).padStart(6, '0');
}

export function secondsLeft(now = Date.now()) {
  return PERIOD - (Math.floor(now / 1000) % PERIOD);
}

export function mountTotp(root: HTMLElement) {
  const secret = root.dataset.totp;
  const codes = root.querySelectorAll<HTMLElement>('[data-totp-code]');
  let interval: number | undefined;
  let counter = -1;
  const tick = async () => {
    const now = Date.now();
    const seconds = secondsLeft(now);
    for (const code of codes) {
      code.querySelector<SVGCircleElement>('[data-totp-ring]')?.style.setProperty('stroke-dashoffset', String(30 - seconds));
      code.toggleAttribute('data-expiring', seconds <= 5);
      const label = code.querySelector('[data-totp-seconds]');
      if (label) label.textContent = String(seconds);
    }
    const current = Math.floor(now / 30000);
    if (current === counter || !secret || !globalThis.crypto?.subtle) return;
    counter = current;
    const value = await totp(secret, now);
    for (const code of codes) {
      const digits = code.querySelector('b');
      if (digits) digits.textContent = `${value.slice(0, 3)} ${value.slice(3)}`;
    }
  };

  tick();
  createAstroMotionLifecycle({
    target: root,
    onChange: (active, { reducedMotion }) => {
      window.clearInterval(interval);
      if (!active && !reducedMotion) return;
      tick();
      interval = window.setInterval(tick, 1000);
    },
  });
}
