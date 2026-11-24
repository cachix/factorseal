const RETRY_MS = 4500;

export function mountAccess(root: HTMLElement) {
  const frame = root.querySelector<HTMLIFrameElement>('[data-live]');
  let timer: number | undefined;

  const restart = () => {
    delete root.dataset.state;
    delete root.dataset.live;
    frame?.contentWindow?.location.reload();
  };

  const receive = (event: MessageEvent) => {
    if (event.source !== frame?.contentWindow || event.data?.type !== 'factorseal:access') {
      return;
    }
    root.dataset.state = event.data.granted ? 'granted' : 'denied';
    window.clearTimeout(timer);
    timer = window.setTimeout(restart, RETRY_MS);
  };

  addEventListener('message', receive);
  return () => {
    window.clearTimeout(timer);
    removeEventListener('message', receive);
  };
}
