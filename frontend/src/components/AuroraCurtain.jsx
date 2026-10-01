/**
 * Snitch — Aurora Curtain background
 * ==================================
 * EN: Northern-lights ribbons drifting behind the graph, rendered as ONE
 *     WebGL2 fragment shader (single draw call, zero extra DOM). Ported
 *     from SmoothUI's "aurora-curtain" (MIT, educlopez/smoothui) and
 *     adapted to plain JSX: no Tailwind (`cn` → inline styles), no
 *     `motion/react` (`useReducedMotion` → prefers-reduced-motion matchMedia).
 *     The render loop pauses when off-screen / tab hidden — it never burns
 *     GPU for nobody.
 * FR: Rubans d'aurore dérivant derrière le graphe, rendus en UN shader de
 *     fragment WebGL2 (un seul draw call, zéro DOM en plus). Porté depuis
 *     « aurora-curtain » de SmoothUI (MIT, educlopez/smoothui), adapté en
 *     JSX pur : pas de Tailwind (`cn` → styles inline), pas de
 *     `motion/react` (`useReducedMotion` → matchMedia
 *     prefers-reduced-motion). La boucle de rendu se met en pause hors
 *     écran / onglet caché — jamais de GPU brûlé pour rien.
 */

import { useEffect, useRef, useState } from "react";

const MAX_DPR = 2;
const MAX_COLORS = 6;
const MAX_BANDS = 8;
const MIN_BANDS = 1;
const MS_PER_SECOND = 1000;
const GRAIN_SHORTHAND = 0.6;
const GRAIN_SEED_CYCLE = 977;
const RGB_MAX = 255;
const DEFAULT_BANDS = 4;
const DEFAULT_SPEED = 1;
const DEFAULT_BLUR = 0.5;
const DEFAULT_INTENSITY = 1;

// EN: Snitch palette — warm orange/pink aurora over the dark slate base.
// FR: Palette Snitch — aurore orangée/rosée sur le fond ardoise sombre.
const DEFAULT_COLORS = ["#fb923c", "#f472b6", "#e879f9"];
const FALLBACK_COLORS = [
  [0.984, 0.573, 0.235],
  [0.957, 0.447, 0.714],
  [0.910, 0.475, 0.976],
];

const VERTEX_SHADER = `#version 300 es
in vec2 aPosition;
void main() {
  gl_Position = vec4(aPosition, 0.0, 1.0);
}`;

// EN: The aurora fragment shader — verbatim from SmoothUI. Each ribbon
//     meanders via 3-octave noise, pinches at both ends, and carries a
//     bright core inside a soft halo. uGrain re-seeds film grain every frame.
// FR: Le shader de fragment aurore — verbatim de SmoothUI. Chaque ruban
//     serpente via du bruit à 3 octaves, se pince aux deux bouts, et porte
//     un noyau lumineux dans un halo doux. uGrain re-seme le grain de film
//     à chaque frame.
const FRAGMENT_SHADER = `#version 300 es
precision highp float;

out vec4 fragColor;

uniform vec2 uRes;
uniform float uTime;
uniform float uBands;
uniform float uSpeed;
uniform float uBlur;
uniform float uIntensity;
uniform float uDirection;
uniform float uGrain;
uniform float uSeed;
uniform float uPixel;
uniform int uColorCount;
uniform vec3 uColors[6];

const int MAX_BANDS = 8;

float hash21(vec2 p) {
  return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453123);
}

float grainHash(vec2 p, float seed) {
  return fract(sin(dot(p, vec2(12.9898, 78.233)) + seed * 1.6180339) * 43758.5453123);
}

float vnoise(vec2 p) {
  vec2 i = floor(p);
  vec2 f = fract(p);
  float a = hash21(i);
  float b = hash21(i + vec2(1.0, 0.0));
  float c = hash21(i + vec2(0.0, 1.0));
  float d = hash21(i + vec2(1.0, 1.0));
  vec2 u = f * f * (3.0 - 2.0 * f);
  return mix(mix(a, b, u.x), mix(c, d, u.x), u.y);
}

float fbm2(vec2 p) {
  float value = vnoise(p) * 0.5 + vnoise(p * 2.07 + 9.31) * 0.25;
  return value * 1.3333333;
}

float fbm3(vec2 p) {
  float value = 0.0;
  float amplitude = 0.5;
  for (int i = 0; i < 3; i++) {
    value += amplitude * vnoise(p);
    p = p * 2.03 + 7.13;
    amplitude *= 0.5;
  }
  return value * 1.1428571;
}

vec3 bandColor(int index) {
  int count = max(uColorCount, 1);
  int slot = index - (index / count) * count;
  return uColors[slot];
}

void main() {
  vec2 uv = gl_FragCoord.xy / uRes;
  float flow = mix(1.0, -1.0, uDirection);
  float y = mix(uv.y, 1.0 - uv.y, uDirection);

  float rise = smoothstep(-0.10, 0.26, y);
  float fade = 1.0 - smoothstep(0.16, 1.08, y);
  float envelope = rise * fade * fade;

  vec3 accum = vec3(0.0);
  float alpha = 0.0;
  float bandCount = clamp(uBands, 1.0, float(MAX_BANDS));
  float spacing = 0.92 / bandCount;
  float t = uTime * uSpeed;

  for (int i = 0; i < MAX_BANDS; i++) {
    if (float(i) >= bandCount) {
      break;
    }
    float fi = float(i);
    float seed = fi * 13.37;

    float driftA = fbm3(vec2(y * 1.35 + seed, t * 0.16 + seed)) - 0.5;
    float driftB = vnoise(vec2(y * 3.40 - seed, t * 0.27 + seed * 0.5)) - 0.5;
    float fold = sin(y * 4.1 + t * 0.42 * flow + seed) * 0.045;
    float center = 0.04 + spacing * (fi + 0.5) + driftA * 0.52 + driftB * 0.18 + fold;

    float widthNoise = fbm2(vec2(y * 2.7 + seed * 2.0, t * 0.22 + seed));
    float pinch = smoothstep(0.0, 0.22, y) * (1.0 - smoothstep(0.55, 1.08, y));
    float width = (0.010 + uBlur * 0.052)
      * mix(0.30, 1.85, widthNoise)
      * (0.45 + 0.75 * pinch);
    width = max(width, 0.0025);

    float dx = (uv.x - center) / width;
    float d2 = dx * dx;
    float core = exp(-d2 * 2.60);
    float halo = exp(-d2 * 0.22);
    float ribbon = core * 1.30 + halo * 0.34;

    float rays = 0.45 + 0.85 * fbm2(vec2(uv.x * 13.0 + seed, y * 1.7 - flow * t * 0.55));
    float breathe = 0.78 + 0.22 * sin(t * 0.31 + seed) * cos(t * 0.17 + seed * 0.7);

    float weight = ribbon * envelope * rays * breathe * 0.46;
    vec3 hot = mix(bandColor(i), vec3(1.0), clamp(core * 0.42, 0.0, 0.45));
    accum += hot * weight;
    alpha += weight;
  }

  float haze = envelope * (1.0 - smoothstep(0.0, 0.58, y)) * 0.10;
  accum += bandColor(0) * haze;
  alpha += haze;

  alpha = clamp(alpha * uIntensity, 0.0, 1.0);
  accum = max(accum * uIntensity, vec3(0.0));

  if (uGrain > 0.0) {
    vec2 cell = floor(gl_FragCoord.xy / max(uPixel, 1.0));
    float g = grainHash(cell, uSeed) + grainHash(cell + vec2(41.7, 17.3), uSeed + 7.31) - 1.0;
    float amp = uGrain * 0.42;

    accum *= 1.0 + g * amp * 1.10;

    float bright = max(g, 0.0) * amp * 0.48;
    float dark = max(-g, 0.0) * amp * 0.34;
    accum += vec3(bright);
    alpha = clamp(alpha + bright + dark, 0.0, 1.0);
  }

  fragColor = vec4(max(accum, vec3(0.0)), alpha);
}`;

const QUAD = new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]);

const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

const toCssColor = (input) =>
  input.trim().startsWith("--") ? `var(${input.trim()})` : input.trim();

const resolveGrain = (noise) =>
  typeof noise === "boolean" ? (noise ? GRAIN_SHORTHAND : 0) : clamp(noise, 0, 1);

// EN: CSS colour → [r,g,b] 0-1, resolved through a hidden probe element +
//     1px canvas (handles var(--token), oklch, named colours uniformly).
// FR: Couleur CSS → [r,g,b] 0-1, résolue via un élément-sonde caché +
//     canvas 1px (gère var(--token), oklch, couleurs nommées uniformément).
const resolveCssColors = (inputs, host) => {
  const probe = document.createElement("span");
  probe.style.display = "none";
  host.append(probe);

  const canvas = document.createElement("canvas");
  canvas.width = 1;
  canvas.height = 1;
  const context = canvas.getContext("2d", { willReadFrequently: true });

  const resolved = inputs.map((input, index) => {
    const fallback = FALLBACK_COLORS[index % FALLBACK_COLORS.length];
    if (!context) return fallback;
    probe.style.color = "";
    probe.style.color = toCssColor(input);
    const computed = window.getComputedStyle(probe).color;
    if (!computed) return fallback;
    context.clearRect(0, 0, 1, 1);
    context.fillStyle = "#000000";
    context.fillStyle = computed;
    context.fillRect(0, 0, 1, 1);
    const { data } = context.getImageData(0, 0, 1, 1);
    return [data[0] / RGB_MAX, data[1] / RGB_MAX, data[2] / RGB_MAX];
  });

  probe.remove();
  return resolved;
};

const compileShader = (gl, type, source) => {
  const shader = gl.createShader(type);
  if (!shader) return null;
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    // EN: Surface the compiler's words — silent failure is how we ended up
    //     debugging a blurry fallback. / FR: Remonter les mots du
    //     compilateur — l'échec silencieux est la cause du flouté à déboguer.
    console.warn("aurora shader compile failed:", gl.getShaderInfoLog(shader));
    gl.deleteShader(shader);
    return null;
  }
  return shader;
};

// EN: Raw WebGL controller — own the GL state outside React so nothing
//     re-renders per frame. Destroy releases the context explicitly.
// FR: Contrôleur WebGL brut — l'état GL vit hors de React pour que rien
//     ne re-render par frame. destroy() libère le contexte explicitement.
const createAuroraController = (canvas) => {
  const gl = canvas.getContext("webgl2", {
    alpha: true,
    antialias: false,
    premultipliedAlpha: true,
  });
  if (!gl) {
    console.warn("aurora: no webgl2 context");
    return null;
  }

  const vertex = compileShader(gl, gl.VERTEX_SHADER, VERTEX_SHADER);
  const fragment = compileShader(gl, gl.FRAGMENT_SHADER, FRAGMENT_SHADER);
  const program = gl.createProgram();
  if (!(vertex && fragment && program)) return null;

  gl.attachShader(program, vertex);
  gl.attachShader(program, fragment);
  gl.linkProgram(program);
  gl.deleteShader(vertex);
  gl.deleteShader(fragment);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    console.warn("aurora program link failed:", gl.getProgramInfoLog(program));
    gl.deleteProgram(program);
    return null;
  }

  gl.useProgram(program);

  const buffer = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  gl.bufferData(gl.ARRAY_BUFFER, QUAD, gl.STATIC_DRAW);
  const position = gl.getAttribLocation(program, "aPosition");
  gl.enableVertexAttribArray(position);
  gl.vertexAttribPointer(position, 2, gl.FLOAT, false, 0, 0);
  gl.enable(gl.BLEND);
  gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);

  const uRes = gl.getUniformLocation(program, "uRes");
  const uTime = gl.getUniformLocation(program, "uTime");
  const uBands = gl.getUniformLocation(program, "uBands");
  const uSpeed = gl.getUniformLocation(program, "uSpeed");
  const uBlur = gl.getUniformLocation(program, "uBlur");
  const uIntensity = gl.getUniformLocation(program, "uIntensity");
  const uDirection = gl.getUniformLocation(program, "uDirection");
  const uGrain = gl.getUniformLocation(program, "uGrain");
  const uSeed = gl.getUniformLocation(program, "uSeed");
  const uPixel = gl.getUniformLocation(program, "uPixel");
  const uColorCount = gl.getUniformLocation(program, "uColorCount");
  const uColors = gl.getUniformLocation(program, "uColors");

  const palette = new Float32Array(MAX_COLORS * 3);
  const startedAt = performance.now();
  let settings = {
    bands: DEFAULT_BANDS,
    blur: DEFAULT_BLUR,
    colors: FALLBACK_COLORS,
    direction: 0,
    grain: 0,
    intensity: DEFAULT_INTENSITY,
    speed: DEFAULT_SPEED,
  };
  let colorCount = FALLBACK_COLORS.length;
  let pixelRatio = 1;
  let grainSeed = 0;
  let frame = 0;
  let running = false;
  let destroyed = false;

  const applyPalette = () => {
    colorCount = clamp(settings.colors.length, 1, MAX_COLORS);
    for (let i = 0; i < colorCount; i++) {
      const rgb = settings.colors[i] ?? FALLBACK_COLORS[0];
      palette[i * 3] = rgb[0];
      palette[i * 3 + 1] = rgb[1];
      palette[i * 3 + 2] = rgb[2];
    }
  };
  applyPalette();

  const resize = () => {
    const rect = canvas.getBoundingClientRect();
    const dpr = Math.min(window.devicePixelRatio || 1, MAX_DPR);
    pixelRatio = dpr;
    const width = Math.max(1, Math.round(rect.width * dpr));
    const height = Math.max(1, Math.round(rect.height * dpr));
    if (canvas.width !== width || canvas.height !== height) {
      canvas.width = width;
      canvas.height = height;
      gl.viewport(0, 0, width, height);
    }
  };

  const draw = () => {
    if (destroyed) return;
    grainSeed = (grainSeed + 1) % GRAIN_SEED_CYCLE;
    gl.clearColor(0, 0, 0, 0);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.uniform2f(uRes, canvas.width, canvas.height);
    gl.uniform1f(uTime, (performance.now() - startedAt) / MS_PER_SECOND);
    gl.uniform1f(uBands, settings.bands);
    gl.uniform1f(uSpeed, settings.speed);
    gl.uniform1f(uBlur, settings.blur);
    gl.uniform1f(uIntensity, settings.intensity);
    gl.uniform1f(uDirection, settings.direction);
    gl.uniform1f(uGrain, settings.grain);
    gl.uniform1f(uSeed, grainSeed);
    gl.uniform1f(uPixel, pixelRatio);
    gl.uniform1i(uColorCount, colorCount);
    gl.uniform3fv(uColors, palette);
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
  };

  const tick = () => {
    if (destroyed || !running) return;
    draw();
    frame = requestAnimationFrame(tick);
  };

  resize();

  return {
    destroy: () => {
      destroyed = true;
      running = false;
      cancelAnimationFrame(frame);
      if (buffer) gl.deleteBuffer(buffer);
      gl.deleteProgram(program);
      // EN: Do NOT loseContext() here — React StrictMode replays mount →
      //     cleanup → mount on the SAME canvas element, and a canvas's GL
      //     context, once lost, can never be re-created. The cleanup that
      //     "releases the context" permanently killed the second mount and
      //     silently dropped us to the blurry CSS fallback. GPU memory is
      //     still freed: deleting the program/buffer is enough, and the
      //     context dies with the canvas element on real unmount.
      // FR: Ne PAS appeler loseContext() ici — React StrictMode rejoue
      //     mount → cleanup → mount sur le MÊME canvas, et un contexte GL
      //     de canvas, une fois perdu, ne peut jamais être recréé. Le
      //     nettoyage qui « libérait le contexte » tuait définitivement le
      //     second montage et nous faisait basculer silencieusement vers
      //     le repli CSS flouté. La mémoire GPU reste libérée : supprimer
      //     programme/buffer suffit, et le contexte meurt avec l'élément
      //     canvas au vrai démontage.
    },
    render: () => {
      resize();
      draw();
    },
    resize: () => {
      resize();
      if (!running) draw();
    },
    setRunning: (next) => {
      if (destroyed || running === next) return;
      running = next;
      if (next) {
        frame = requestAnimationFrame(tick);
      } else {
        cancelAnimationFrame(frame);
      }
    },
    setSettings: (next) => {
      settings = next;
      applyPalette();
    },
  };
};

// EN: prefers-reduced-motion without motion/react — subscribe to the media
//     query, honour the OS-level accessibility setting.
// FR: prefers-reduced-motion sans motion/react — abonnement à la media
//     query, respect du réglage d'accessibilité de l'OS.
function useReducedMotionPref() {
  const [reduced, setReduced] = useState(
    () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false
  );
  useEffect(() => {
    const mq = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    if (!mq) return;
    const onChange = () => setReduced(mq.matches);
    mq.addEventListener?.("change", onChange);
    return () => mq.removeEventListener?.("change", onChange);
  }, []);
  return reduced;
}

/**
 * EN: Decorative aurora backdrop. Children render ABOVE the canvas; the
 *     curtain itself is pointer-events-none and aria-hidden by construction.
 * FR: Toile de fond aurora décorative. Les enfants sont rendus AU-DESSUS du
 *     canvas ; le rideau est pointer-events-none et aria-hidden par
 *     construction.
 */
export default function AuroraCurtain({
  bands = DEFAULT_BANDS,
  blur = DEFAULT_BLUR,
  children,
  colors = DEFAULT_COLORS,
  direction = "up",
  intensity = DEFAULT_INTENSITY,
  noise = 0,
  paused = false,
  speed = DEFAULT_SPEED,
  style,
}) {
  const shouldReduceMotion = useReducedMotionPref();
  const hostRef = useRef(null);
  const canvasRef = useRef(null);
  const controllerRef = useRef(null);
  const [isSupported, setIsSupported] = useState(true);
  const [isActive, setIsActive] = useState(false);
  const [resolvedColors, setResolvedColors] = useState(FALLBACK_COLORS);

  const colorKey = colors.join("|");
  const grain = resolveGrain(noise);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    setResolvedColors(resolveCssColors(colorKey.split("|"), host));
  }, [colorKey]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const controller = createAuroraController(canvas);
    controllerRef.current = controller;
    setIsSupported(controller !== null);
    if (!controller) return;

    const observer = new ResizeObserver(() => controller.resize());
    observer.observe(canvas);
    return () => {
      observer.disconnect();
      controller.destroy();
      controllerRef.current = null;
    };
  }, []);

  useEffect(() => {
    const host = hostRef.current;
    if (!(host && isSupported)) return;

    let isOnScreen = true;
    const sync = () =>
      setIsActive(isOnScreen && document.visibilityState === "visible");

    const observer = new IntersectionObserver((entries) => {
      isOnScreen = entries.some((entry) => entry.isIntersecting);
      sync();
    });
    observer.observe(host);
    document.addEventListener("visibilitychange", sync);
    sync();

    return () => {
      observer.disconnect();
      document.removeEventListener("visibilitychange", sync);
    };
  }, [isSupported]);

  useEffect(() => {
    const controller = controllerRef.current;
    if (!controller) return;
    controller.setSettings({
      bands: clamp(Math.round(bands), MIN_BANDS, MAX_BANDS),
      blur: clamp(blur, 0, 1),
      colors: resolvedColors,
      direction: direction === "down" ? 1 : 0,
      grain,
      intensity: clamp(intensity, 0, 1),
      speed: Math.max(speed, 0),
    });
    controller.render();
  }, [bands, blur, direction, grain, intensity, resolvedColors, speed]);

  useEffect(() => {
    const controller = controllerRef.current;
    if (!controller) return;
    const shouldRun = isActive && !paused && !shouldReduceMotion;
    controller.setRunning(shouldRun);
    if (!shouldRun) controller.render();
  }, [isActive, paused, shouldReduceMotion]);

  // EN: CSS radial-gradient fallback when WebGL2 is unavailable.
  // FR: Repli en dégradé radial CSS quand WebGL2 est indisponible.
  const fallbackBackground = colors
    .map((color, index) => {
      const x = 14 + index * (72 / Math.max(colors.length, 1));
      const y = direction === "up" ? 108 : -8;
      return `radial-gradient(58% 96% at ${x}% ${y}%, ${toCssColor(color)} 0%, transparent 68%)`;
    })
    .join(", ");

  return (
    <div
      ref={hostRef}
      style={{ position: "relative", isolation: "isolate", overflow: "hidden", ...style }}
    >
      {isSupported ? (
        <div
          aria-hidden="true"
          style={{ pointerEvents: "none", position: "absolute", inset: 0 }}
        >
          <canvas ref={canvasRef} style={{ height: "100%", width: "100%" }} />
        </div>
      ) : (
        <div
          aria-hidden="true"
          style={{
            pointerEvents: "none", position: "absolute", inset: 0,
            opacity: 0.7, filter: "blur(40px)",
            backgroundImage: fallbackBackground,
          }}
        />
      )}
      <div style={{ position: "relative", zIndex: 10, height: "100%" }}>
        {children}
      </div>
    </div>
  );
}
