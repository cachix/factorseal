const VIEWBOX = 160;
const KEYHOLE_OFFSET_Y = 65.644 - VIEWBOX / 2;
const WIDTH = 260;
const HEIGHT = 104;

const markBody = new Path2D('M37 32H123A5 5 0 0 1 128 37V123A5 5 0 0 1 123 128H37A5 5 0 0 1 32 123V37A5 5 0 0 1 37 32Z M80 50 C71.36 50 64.356 57.004 64.356 65.644 C64.356 72.097 68.263 77.636 73.84 80.028 L69.142 110 H91.965 L86.702 79.783 C91.988 77.273 95.644 71.886 95.644 65.644 C95.644 57.004 88.64 50 80 50 Z');
const markPins: [number, number, number, number][] = [
  [56, 16, 16, 24], [88, 16, 16, 24], [56, 120, 16, 24], [88, 120, 16, 24],
  [16, 56, 24, 16], [16, 88, 24, 16], [120, 56, 24, 16], [120, 88, 24, 16],
];

interface Vertex { x: number; y: number; z: number }
interface Face { vertices: Vertex[]; shade: number }

const vertex = (x: number, y: number, z: number): Vertex => ({ x, y, z });
const turn = ({ x, y, z }: Vertex, angle: number) => vertex(x * Math.cos(angle) - y * Math.sin(angle), x * Math.sin(angle) + y * Math.cos(angle), z);
const depth = ({ x, y, z }: Vertex) => x * 0.8 - y * 0.24 + z;

function smooth(phase: number, start: number, end: number) {
  const progress = Math.min(1, Math.max(0, (phase - start) / (end - start)));
  return progress * progress * (3 - 2 * progress);
}

function shaded(vertices: Vertex[]): Face {
  const edge = (a: Vertex, b: Vertex) => vertex(b.x - a.x, b.y - a.y, b.z - a.z);
  const first = edge(vertices[0], vertices[1]);
  const second = edge(vertices[0], vertices[2]);
  const normal = vertex(
    first.y * second.z - first.z * second.y,
    first.z * second.x - first.x * second.z,
    first.x * second.y - first.y * second.x,
  );
  const length = Math.hypot(normal.x, normal.y, normal.z);
  const light = (-0.4 * normal.x - 0.65 * normal.y + 0.65 * normal.z) * Math.sign(depth(normal)) / Math.max(length, 0.001);
  return { vertices, shade: 0.08 + 0.1 * (1 - Math.min(1, Math.max(-1, light))) };
}

function solid(faces: Face[], front: Vertex[], back: Vertex[]) {
  faces.push({ vertices: back, shade: 0 });
  front.forEach((_, index) => {
    const next = (index + 1) % front.length;
    faces.push(shaded([front[index], back[index], back[next], front[next]]));
  });
  faces.push({ vertices: front, shade: 0 });
}

function bowPoint(step: number, halfWidth: number, halfHeight: number, radius: number): [number, number] {
  const corner = Math.floor(step / 8) % 4;
  const angle = -Math.PI / 2 + corner * Math.PI / 2 + (step % 8) * Math.PI / 16;
  const x = corner < 2 ? halfWidth - radius : radius - halfWidth;
  const z = corner === 0 || corner === 3 ? radius - halfHeight : halfHeight - radius;
  return [x + radius * Math.cos(angle), 128 + z + radius * Math.sin(angle)];
}

function key(phase: number) {
  const faces: Face[] = [];
  const insertion = smooth(phase, 0.18, 0.44) - smooth(phase, 0.9, 0.99);
  const angle = (smooth(phase, 0.54, 0.69) - smooth(phase, 0.79, 0.87)) * Math.PI * 0.5;
  const tip = 54 - insertion * 112;
  const plate = (outline: [number, number][]) => {
    const layer = (y: number) => outline.map(([x, z]) => turn(vertex(y, x, Math.max(z + tip, 3)), angle));
    solid(faces, layer(-3.5), layer(3.5));
  };
  plate([[-4.5, 0], [4.5, 0], [4.5, 103], [-4.5, 103]]);
  for (const z of [6, 20, 34]) {
    if (tip + z + 8 > 3) plate([[4.5, z], [14, z], [14, z + 8], [4.5, z + 8]]);
  }
  for (let step = 0; step < 32; step += 1) {
    plate([bowPoint(step, 28, 32, 3), bowPoint(step + 1, 28, 32, 3), bowPoint(step + 1, 18, 22, 2), bowPoint(step, 18, 22, 2)]);
  }
  return faces;
}

function paintMark(context: CanvasRenderingContext2D, reveal: number, ink: string) {
  const scale = (72 - 20 * reveal) / VIEWBOX;
  context.save();
  context.translate(WIDTH / 2 + 20 * reveal, HEIGHT / 2);
  context.scale(scale, scale);
  context.translate(-VIEWBOX / 2, -VIEWBOX / 2);
  context.fillStyle = ink;
  context.fill(markBody, 'evenodd');
  for (const [x, y, width, height] of markPins) {
    context.beginPath();
    context.roundRect(x, y, width, height, 2);
    context.fill();
  }
  context.restore();
}

function paint(context: CanvasRenderingContext2D, reveal: number, phase: number, ink: [number, number, number]) {
  const [hue, saturation, lightness] = ink;
  context.clearRect(0, 0, WIDTH, HEIGHT);
  paintMark(context, reveal, `hsl(${hue} ${saturation}% ${lightness}%)`);
  const opacity = smooth(reveal, 0.8, 1);
  if (opacity === 0) return;
  const faces = key(phase);
  const average = (face: Face) => face.vertices.reduce((sum, v) => sum + depth(v), 0) / face.vertices.length;
  faces.sort((left, right) => average(left) - average(right));
  const scale = (72 + 28 * reveal) / VIEWBOX;
  const keyholeY = KEYHOLE_OFFSET_Y * (72 - 20 * reveal) / VIEWBOX;
  for (const face of faces) {
    const project = (v: Vertex): [number, number] => [
      WIDTH / 2 + 20 * reveal + (v.x - v.z * 0.8) * scale,
      HEIGHT / 2 + (v.y + v.x * 0.3) * scale + keyholeY,
    ];
    const tone = lightness > 50 ? lightness - face.shade * 100 : lightness + face.shade * 100;
    context.beginPath();
    context.moveTo(...project(face.vertices[0]));
    for (const v of face.vertices.slice(1)) context.lineTo(...project(v));
    context.closePath();
    context.fillStyle = `hsl(${hue} ${saturation}% ${Math.min(100, Math.max(0, tone))}% / ${opacity})`;
    context.fill();
  }
}

function hsl(color: string): [number, number, number] {
  const [r, g, b] = (color.match(/\d+(\.\d+)?/g) ?? ['0', '0', '0']).slice(0, 3).map((value) => Number(value) / 255);
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const lightness = (max + min) / 2;
  if (max === min) return [0, 0, lightness * 100];
  const delta = max - min;
  const saturation = lightness > 0.5 ? delta / (2 - max - min) : delta / (max + min);
  const hue = max === r ? (g - b) / delta + (g < b ? 6 : 0) : max === g ? (b - r) / delta + 2 : (r - g) / delta + 4;
  return [hue * 60, saturation * 100, lightness * 100];
}

export function unlockArt(canvas: HTMLCanvasElement) {
  const context = canvas.getContext('2d');
  let frame = 0;
  const stop = () => {
    cancelAnimationFrame(frame);
    frame = 0;
  };
  const start = () => {
    if (!context) return;
    stop();
    const ratio = window.devicePixelRatio || 1;
    canvas.width = WIDTH * ratio;
    canvas.height = HEIGHT * ratio;
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    const ink = hsl(getComputedStyle(canvas).color);
    const began = performance.now();
    const tick = (now: number) => {
      const elapsed = now - began;
      paint(context, smooth(elapsed / 450, 0, 1), (elapsed / 3000) % 1, ink);
      frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
  };
  return { start, stop };
}
