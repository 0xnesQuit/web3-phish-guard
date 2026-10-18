// Dependency-free icon renderer: a shield with a check mark, rasterised with 4x4 supersampling.
// Also writes public/icons/logo.svg (same geometry) for store listings.
import { writeFileSync, mkdirSync } from "node:fs";
import { deflateSync } from "node:zlib";

// ---- geometry (in a 100x100 box) ----------------------------------------------
const SHIELD = (() => {
  // classic shield: rounded top corners, straight sides for the upper 40%, then a smooth curve to the tip
  const pts = [];
  const R = 8;
  for (let i = 0; i <= 8; i++) { const a = Math.PI + (i / 8) * (Math.PI / 2); pts.push([16 + R + R * Math.cos(a), 12 + R + R * Math.sin(a)]); } // top-left corner
  for (let i = 0; i <= 8; i++) { const a = -Math.PI / 2 + (i / 8) * (Math.PI / 2); pts.push([84 - R + R * Math.cos(a), 12 + R + R * Math.sin(a)]); } // top-right corner
  for (let i = 1; i <= 30; i++) { const t = i / 30; const y = 20 + 74 * t; const k = Math.max(0, (t - 0.35) / 0.65); pts.push([84 - 34 * Math.pow(k, 1.45), y]); }
  for (let i = 29; i >= 1; i--) { const t = i / 30; const y = 20 + 74 * t; const k = Math.max(0, (t - 0.35) / 0.65); pts.push([16 + 34 * Math.pow(k, 1.45), y]); }
  return pts;
})();

function inPolygon(x, y, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i], [xj, yj] = poly[j];
    if (yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}
function distSeg(px, py, ax, ay, bx, by) {
  const vx = bx - ax, vy = by - ay, wx = px - ax, wy = py - ay;
  const t = Math.max(0, Math.min(1, (vx * wx + vy * wy) / (vx * vx + vy * vy)));
  const dx = ax + t * vx - px, dy = ay + t * vy - py;
  return Math.hypot(dx, dy);
}
const CHECK = [[32, 50], [45, 63], [68, 37]];
const lerp = (a, b, t) => a + (b - a) * t;

/** Returns [r,g,b,a] for a point in the 100x100 box. */
function shade(x, y) {
  if (!inPolygon(x, y, SHIELD)) return [0, 0, 0, 0];
  // inner rim: slightly lighter border
  const edge = Math.min(...[...SHIELD.keys()].map((i) => distSeg(x, y, ...SHIELD[i], ...SHIELD[(i + 1) % SHIELD.length])));
  const t = (y - 12) / 82;
  let r = lerp(0x2f, 0x5b, t), g = lerp(0x6f, 0x21, t), b = lerp(0xf0, 0xb6, t); // blue -> violet
  if (edge < 3.2) { r = lerp(r, 255, 0.35); g = lerp(g, 255, 0.35); b = lerp(b, 255, 0.35); }
  const d = Math.min(distSeg(x, y, ...CHECK[0], ...CHECK[1]), distSeg(x, y, ...CHECK[1], ...CHECK[2]));
  if (d < 6.8) return [255, 255, 255, 255];
  if (d < 7.6) { const k = (7.6 - d) / 0.8; return [lerp(r, 255, k), lerp(g, 255, k), lerp(b, 255, k), 255]; }
  return [r, g, b, 255];
}

// ---- PNG encoding -------------------------------------------------------------------
function crc32(buf) {
  let c, crc = 0xffffffff;
  for (let n = 0; n < buf.length; n++) { c = (crc ^ buf[n]) & 0xff; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crc = (crc >>> 8) ^ c; }
  return (crc ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function png(size) {
  const raw = Buffer.alloc((size * 4 + 1) * size);
  const SS = 4;
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    for (let x = 0; x < size; x++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < SS; sy++) for (let sx = 0; sx < SS; sx++) {
        const px = ((x + (sx + 0.5) / SS) / size) * 100, py = ((y + (sy + 0.5) / SS) / size) * 100;
        const [cr, cg, cb, ca] = shade(px, py);
        r += cr * ca; g += cg * ca; b += cb * ca; a += ca;
      }
      const i = y * (size * 4 + 1) + 1 + x * 4;
      if (a > 0) { raw[i] = Math.round(r / a); raw[i + 1] = Math.round(g / a); raw[i + 2] = Math.round(b / a); raw[i + 3] = Math.round(a / (SS * SS)); }
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4); ihdr[8] = 8; ihdr[9] = 6;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}

mkdirSync("public/icons", { recursive: true });
for (const s of [16, 32, 48, 128, 256, 512]) writeFileSync(`public/icons/icon${s}.png`, png(s));

const svgPath = SHIELD.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ") + " Z";
writeFileSync("public/icons/logo.svg", `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="512" height="512">
  <defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#2f6ff0"/><stop offset="1" stop-color="#5b21b6"/></linearGradient></defs>
  <path d="${svgPath}" fill="url(#g)" stroke="#ffffff" stroke-opacity="0.35" stroke-width="3" stroke-linejoin="round"/>
  <polyline points="32,50 45,63 68,37" fill="none" stroke="#ffffff" stroke-width="13" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
`);
console.log("icons written (16/32/48/128/256/512 + logo.svg)");
