import icon from '../../../assets/logo/factorseal-app-icon.svg?raw';

export function GET() {
  return new Response(icon, { headers: { 'Content-Type': 'image/svg+xml' } });
}
