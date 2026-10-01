/**
 * Snitch — application icon generator.
 *
 * EN: Draws electron/icon.png (256×256 RGBA) from scratch using only Node.js
 *     built-ins — no image library needed. The icon is a wireframe sphere
 *     ringed by nodes, matching the splash screen.
 *
 *     Run: node generate-icon.js
 *
 * FR: Dessine electron/icon.png (256×256 RGBA) à partir de zéro avec les
 *     modules Node.js intégrés uniquement — aucune lib d'image nécessaire.
 *     L'icône est une sphère filaire entourée de nœuds, assortie au splash.
 *
 *     Usage : node generate-icon.js
 */

const zlib = require('zlib')
const fs   = require('fs')
const path = require('path')

const S = 512
// EN: RGBA pixel buffer, fully transparent. / FR: buffer de pixels RGBA, entièrement transparent.
const buf = Buffer.alloc(S * S * 4, 0)

/**
 * EN: Alpha-composite one pixel over the buffer (source-over blending).
 * FR: Composite un pixel en alpha au-dessus du buffer (mélange source-over).
 */
function px(x, y, r, g, b, a) {
  x = Math.round(x); y = Math.round(y)
  if (x < 0 || x >= S || y < 0 || y >= S || a <= 0) return
  const i = (y * S + x) * 4
  const sa = a / 255, da = buf[i+3] / 255
  const oa = sa + da * (1 - sa)
  if (oa < 0.001) return
  buf[i]   = Math.round((r * sa + buf[i]   * da * (1 - sa)) / oa)
  buf[i+1] = Math.round((g * sa + buf[i+1] * da * (1 - sa)) / oa)
  buf[i+2] = Math.round((b * sa + buf[i+2] * da * (1 - sa)) / oa)
  buf[i+3] = Math.round(oa * 255)
}

/** EN: Filled circle with 1px antialiased edge. / FR: Cercle plein avec bord anticrénelé de 1 px. */
function fillCircle(cx, cy, R, r, g, b, a) {
  for (let y = Math.ceil(cy - R - 1); y <= cy + R + 1; y++)
    for (let x = Math.ceil(cx - R - 1); x <= cx + R + 1; x++) {
      const d = Math.sqrt((x-cx)**2 + (y-cy)**2)
      if (d < R + 0.5) px(x, y, r, g, b, Math.round(a * Math.min(1, R + 0.5 - d)))
    }
}

/** EN: Ring of stroke width `sw`. / FR: Anneau d'épaisseur `sw`. */
function strokeCircle(cx, cy, R, sw, r, g, b, a) {
  for (let y = Math.ceil(cy - R - sw - 1); y <= cy + R + sw + 1; y++)
    for (let x = Math.ceil(cx - R - sw - 1); x <= cx + R + sw + 1; x++) {
      const d = Math.sqrt((x-cx)**2 + (y-cy)**2)
      const dist = Math.abs(d - R)
      if (dist < sw/2 + 0.5) px(x, y, r, g, b, Math.round(a * Math.min(1, sw/2 + 0.5 - dist)))
    }
}

/** EN: Straight line via linear interpolation. / FR: Ligne droite par interpolation linéaire. */
function drawLine(x0, y0, x1, y1, r, g, b, a) {
  const dx = x1-x0, dy = y1-y0
  const steps = Math.ceil(Math.sqrt(dx*dx + dy*dy)) * 2
  for (let i = 0; i <= steps; i++) {
    const t = i / steps
    px(x0 + t*dx, y0 + t*dy, r, g, b, a)
  }
}

/** EN: Ellipse outline — used for the sphere's lat/long wireframe. / FR: Contour d'ellipse — pour le filaire lat/long de la sphère. */
function drawEllipse(cx, cy, rx, ry, r, g, b, a) {
  const steps = Math.ceil(Math.PI * (rx + ry) * 2.5)
  for (let i = 0; i < steps; i++) {
    const t = (i / steps) * Math.PI * 2
    px(cx + rx * Math.cos(t), cy + ry * Math.sin(t), r, g, b, a)
  }
}

const cx = S / 2, cy = S / 2
const R = 184  // EN: sphere radius / FR: rayon de la sphère

// ── Rounded-square black background / Fond noir à coins arrondis ─────────────
const cornerR = 100
for (let y = 0; y < S; y++)
  for (let x = 0; x < S; x++) {
    const dx = Math.abs(x - cx) - (cx - cornerR)
    const dy = Math.abs(y - cy) - (cy - cornerR)
    const d  = dx > 0 && dy > 0 ? Math.sqrt(dx*dx + dy*dy) : Math.max(dx, dy, 0)
    if (d <= cornerR) { const i=(y*S+x)*4; buf[i]=0;buf[i+1]=0;buf[i+2]=0;buf[i+3]=255 }
  }

// ── Latitude lines / Lignes de latitude ──────────────────────────────────────
for (const ry_f of [0.28, 0.63, 0.92])
  drawEllipse(cx, cy, R, R * ry_f, 255, 255, 255, 38)

// ── Longitude lines / Lignes de longitude ────────────────────────────────────
for (const rx_f of [0.32, 0.74])
  drawEllipse(cx, cy, R * rx_f, R, 255, 255, 255, 38)

// ── Sphere ring / Anneau de la sphère ────────────────────────────────────────
strokeCircle(cx, cy, R, 5.6, 255, 255, 255, 190)

// ── Peripheral nodes / Nœuds périphériques ───────────────────────────────────
const scale = R / 118
function svgPt(sx, sy) { return [cx + (sx-240)*scale, cy + (sy-210)*scale] }
const nodes = [
  svgPt(155,110), svgPt(332,118), svgPt(355,230),
  svgPt(308,300), svgPt(158,298), svgPt(124,175),
]

// EN: Ring lines between adjacent nodes. / FR: Lignes d'anneau entre nœuds adjacents.
for (let i = 0; i < nodes.length; i++) {
  const [ax,ay] = nodes[i], [bx,by] = nodes[(i+1) % nodes.length]
  drawLine(ax, ay, bx, by, 255, 255, 255, 55)
}
// EN: Spokes to center. / FR: Rayons vers le centre.
for (const [nx,ny] of nodes) drawLine(cx, cy, nx, ny, 255, 255, 255, 38)

for (const [nx,ny] of nodes) {
  fillCircle(nx, ny, 11, 0, 0, 0, 255)
  strokeCircle(nx, ny, 11, 3.6, 255, 255, 255, 210)
  fillCircle(nx, ny, 5.6, 247, 176, 22, 255)
}

// ── Center node / Nœud central ───────────────────────────────────────────────
fillCircle(cx, cy, 36, 247, 176, 22, 45)
fillCircle(cx, cy, 22, 247, 176, 22, 155)
fillCircle(cx, cy, 14, 247, 176, 22, 255)
fillCircle(cx, cy, 6,  255, 255, 255, 255)

// ── PNG encoding / Encodage PNG ──────────────────────────────────────────────
// EN: Minimal hand-rolled PNG writer: signature + IHDR + IDAT + IEND with
//     CRC32 checksums. Avoids pulling in a whole image dependency.
// FR: Encodeur PNG minimal fait main : signature + IHDR + IDAT + IEND avec
//     sommes CRC32. Évite d'ajouter toute une dépendance d'image.
function crc32(data) {
  const T = new Int32Array(256)
  for (let i = 0; i < 256; i++) {
    let c = i
    for (let j = 0; j < 8; j++) c = c & 1 ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1)
    T[i] = c
  }
  let crc = -1
  for (const b of data) crc = T[(crc ^ b) & 0xFF] ^ (crc >>> 8)
  return (crc ^ -1) >>> 0
}

function ck(type, data) {
  const tb   = Buffer.from(type, 'ascii')
  const body = Buffer.concat([tb, data])
  const len  = Buffer.alloc(4); len.writeUInt32BE(data.length)
  const crc  = Buffer.alloc(4); crc.writeUInt32BE(crc32(body))
  return Buffer.concat([len, body, crc])
}

const ihdr = Buffer.alloc(13)
ihdr.writeUInt32BE(S, 0); ihdr.writeUInt32BE(S, 4)
ihdr[8] = 8; ihdr[9] = 6  // EN: 8-bit RGBA / FR: RGBA 8 bits

const raw = []
for (let y = 0; y < S; y++) {
  raw.push(0)  // EN: PNG filter type: None / FR: filtre PNG : None
  for (let x = 0; x < S; x++) {
    const i = (y*S+x)*4
    raw.push(buf[i], buf[i+1], buf[i+2], buf[i+3])
  }
}

const png = Buffer.concat([
  Buffer.from([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A]),
  ck('IHDR', ihdr),
  ck('IDAT', zlib.deflateSync(Buffer.from(raw), { level: 9 })),
  ck('IEND', Buffer.alloc(0)),
])

const out = path.join(__dirname, 'icon.png')
fs.writeFileSync(out, png)
console.log('Generated', out, '-', png.length, 'bytes')
