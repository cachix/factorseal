export function mountLive(root: HTMLElement) {
  const frame = root.querySelector<HTMLIFrameElement>('[data-live]');
  if (!frame?.dataset.src || !matchMedia('(min-width: 60rem) and (pointer: fine)').matches) {
    return () => {};
  }
  const ready = (event: MessageEvent) => {
    if (event.source === frame.contentWindow && event.data === 'factorseal:ready') {
      root.dataset.live = 'ready';
    }
  };
  addEventListener('message', ready);
  frame.src = frame.dataset.src;
  return () => removeEventListener('message', ready);
}
