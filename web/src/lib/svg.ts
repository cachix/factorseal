export function inlineSvg(raw: string, className?: string) {
  return raw
    .replace(/<\?xml[^>]*\?>\s*/, '')
    .replace(/<title[^>]*>[\s\S]*?<\/title>\s*/g, '')
    .replace(/<desc[^>]*>[\s\S]*?<\/desc>\s*/g, '')
    .replace(/\s(?:role|aria-labelledby)="[^"]*"/g, '')
    .replace('<svg', `<svg aria-hidden="true" focusable="false"${className ? ` class="${className}"` : ''}`);
}
