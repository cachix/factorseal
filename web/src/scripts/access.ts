const AUTHORIZING_MS = 700;
const RETRY_MS = 4500;

export function mountAccess(root: HTMLElement) {
  let timer: number | undefined;

  const show = (state: string) => {
    window.clearTimeout(timer);
    root.dataset.state = state;
    if (state === 'denied' || state === 'revoked') timer = window.setTimeout(() => show('request'), RETRY_MS);
  };

  const choose = (lifetime: string) => {
    root.dataset.lifetime = lifetime;
    for (const choice of root.querySelectorAll<HTMLElement>('[data-lifetime-choice]')) {
      choice.setAttribute('aria-pressed', String(choice.dataset.lifetimeChoice === lifetime));
    }
  };

  root.addEventListener('click', (event) => {
    const target = event.target as Element;
    const choice = target.closest<HTMLElement>('[data-lifetime-choice]');
    if (choice?.dataset.lifetimeChoice && root.dataset.state === 'request') choose(choice.dataset.lifetimeChoice);
    else if (target.closest('[data-grant]') && root.dataset.state === 'request') {
      show('authorizing');
      timer = window.setTimeout(() => show('granted'), AUTHORIZING_MS);
    } else if (target.closest('[data-deny]') && root.dataset.state === 'request') show('denied');
    else if (target.closest('[data-revoke]') && root.dataset.state === 'granted') show('revoked');
  });
}
