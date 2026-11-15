export function mountOnPageLoad(selector: string, mount: (root: HTMLElement) => () => void) {
  document.addEventListener('astro:page-load', () => {
    const unmounts = [...document.querySelectorAll<HTMLElement>(selector)].map((root) => mount(root));
    document.addEventListener('astro:before-swap', () => unmounts.forEach((unmount) => unmount()), { once: true });
  });
}
