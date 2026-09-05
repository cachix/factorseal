const sizeLab = document.getElementById('size-lab');
const previewButtons = document.querySelectorAll('[data-preview]');

for (const button of previewButtons) {
  button.addEventListener('click', () => {
    const theme = button.dataset.preview;
    const color = theme === 'dark' ? 'paper' : 'ink';
    sizeLab.dataset.theme = theme;
    for (const control of previewButtons) {
      control.setAttribute('aria-pressed', String(control === button));
    }
    for (const mark of sizeLab.querySelectorAll('[data-mark]')) {
      const suffix = mark.dataset.mark === 'micro' ? '-micro' : '';
      mark.src = `../logo/factorseal-mark${suffix}-${color}.svg`;
    }
  });
}

document.getElementById('print-guide').addEventListener('click', () => window.print());
