// Landing — the MIRGAB falcon eye.
// The original falcon artwork (transparent PNG) sits in a 3D stage that tilts toward the pointer. Live SVG layers are
// drawn exactly over its eye: rotating iris rings, a radar sweep, a scan line and a pupil that follows the pointer,
// plus outer radar arcs and pings. "Enter" flies the camera into the pupil until it fills the screen, then reveals the
// platform. No external libraries (CSP-safe); reduced-motion users get a calm static version and a simple fade.
import { h, langPicker, t } from "./core.js";

const REDUCED = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
const NS = "http://www.w3.org/2000/svg";
// geometry of assets/falcon.png (835 × 510), measured from the artwork
const W0 = 835, H0 = 510;
const IRIS = { x: 463, y: 209, r: 104 };
const PUPIL = { x: 475, y: 166, r: 34 };
const EYE = { x: 448, y: 201, rx: 172, ry: 92 };

let scene = null;
export function stopLanding() { scene?.stop(); scene = null; }

function s(tag, attrs = {}, ...kids) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  kids.flat().forEach((c) => c && el.append(c));
  return el;
}

function ticks(cx, cy, r, n, len, cls) {
  return s("g", { class: cls }, ...Array.from({ length: n }, (_, i) => {
    const a = (i / n) * Math.PI * 2, l = i % 6 === 0 ? len * 2 : len;
    return s("line", { x1: cx + Math.cos(a) * r, y1: cy + Math.sin(a) * r, x2: cx + Math.cos(a) * (r - l), y2: cy + Math.sin(a) * (r - l) });
  }));
}

function sector(cx, cy, r, a0, a1) {
  const p = (a) => `${cx + Math.cos(a) * r} ${cy + Math.sin(a) * r}`;
  return `M ${cx} ${cy} L ${p(a0)} A ${r} ${r} 0 0 1 ${p(a1)} Z`;
}

// day / night switch on the entrance (same setting as the platform's sun / moon button)
const SUN = '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M5.3 18.7l1.6-1.6M17.1 6.9l1.6-1.6"/></svg>';
const MOON = '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M20.5 14.6A8.5 8.5 0 0 1 9.4 3.5a8.5 8.5 0 1 0 11.1 11.1Z"/></svg>';
function themeBtn() {
  const b = h("button", { class: "ld-theme", type: "button" });
  const paint = () => {
    const dark = document.documentElement.classList.contains("dark");
    b.innerHTML = dark ? SUN : MOON;                    // static icons only
    b.setAttribute("aria-label", t(dark ? "theme.to_light" : "theme.to_dark")); b.title = b.getAttribute("aria-label");
  };
  b.addEventListener("click", () => {
    const dark = !document.documentElement.classList.contains("dark");
    document.documentElement.classList.toggle("dark", dark);
    try { localStorage.setItem("mirqab.theme", dark ? "dark" : "light"); } catch {}
    paint();
  });
  paint();
  return b;
}

function falconStage() {
  const eyeSvg = s("svg", { class: "fx-svg", viewBox: `0 0 ${W0} ${H0}`, "aria-hidden": "true" },
    s("defs", {},
      s("clipPath", { id: "fx-eye" }, s("ellipse", { cx: EYE.x, cy: EYE.y, rx: EYE.rx, ry: EYE.ry })),
      s("radialGradient", { id: "fx-pg", cx: "40%", cy: "35%", r: "70%" },
        s("stop", { offset: "0", "stop-color": "#5ff3ff" }), s("stop", { offset: ".45", "stop-color": "#0a6f8a" }), s("stop", { offset: "1", "stop-color": "#021018" })),
      s("radialGradient", { id: "fx-glow" }, s("stop", { offset: "0", "stop-color": "#22d3ee", "stop-opacity": ".55" }), s("stop", { offset: "1", "stop-color": "#22d3ee", "stop-opacity": "0" })),
      s("linearGradient", { id: "fx-sw", x1: "0", y1: "0", x2: "1", y2: "0" },
        s("stop", { offset: "0", "stop-color": "#22d3ee", "stop-opacity": "0" }), s("stop", { offset: "1", "stop-color": "#7df9ff", "stop-opacity": ".55" }))),
    s("image", { href: "/assets/falcon.png", x: 0, y: 0, width: W0, height: H0 }),
    s("g", { "clip-path": "url(#fx-eye)" },
      s("circle", { class: "fx-iglow", cx: IRIS.x, cy: IRIS.y, r: IRIS.r * 1.25, fill: "url(#fx-glow)" }),
      s("g", { class: "fx-spin" }, s("circle", { class: "fx-ring", cx: IRIS.x, cy: IRIS.y, r: IRIS.r, "stroke-dasharray": "3 9" }),
        ticks(IRIS.x, IRIS.y, IRIS.r - 6, 60, 6, "fx-ticks")),
      s("g", { class: "fx-spin-rev" }, s("circle", { class: "fx-ring2", cx: IRIS.x, cy: IRIS.y, r: IRIS.r * 0.74, "stroke-dasharray": "40 14 6 14" })),
      s("g", { class: "fx-sweep" }, s("path", { d: sector(IRIS.x, IRIS.y, IRIS.r * 1.05, -0.55, 0), fill: "url(#fx-sw)" })),
      s("rect", { class: "fx-scan", x: EYE.x - EYE.rx, y: EYE.y - EYE.ry, width: EYE.rx * 2, height: 3, rx: 1.5 }),
      s("g", { class: "fx-pupil" },
        s("circle", { class: "fx-pring", cx: PUPIL.x, cy: PUPIL.y, r: PUPIL.r + 7 }),
        s("circle", { cx: PUPIL.x, cy: PUPIL.y, r: PUPIL.r, fill: "url(#fx-pg)" }),
        s("circle", { class: "fx-core", cx: PUPIL.x, cy: PUPIL.y + 3, r: PUPIL.r * 0.42 }),
        s("ellipse", { class: "fx-glint", cx: PUPIL.x - 11, cy: PUPIL.y - 13, rx: 10, ry: 6 }))));
  // outer radar arcs float on their own plane (parallax)
  const arcs = s("svg", { class: "fx-svg fx-arcs", viewBox: `0 0 ${W0} ${H0}`, "aria-hidden": "true" },
    s("g", { class: "fx-orbit" }, s("circle", { class: "fx-arc", cx: IRIS.x, cy: IRIS.y, r: 232, "stroke-dasharray": "2 7", pathLength: 1000 })),
    s("g", { class: "fx-orbit-rev" }, s("circle", { class: "fx-arc2", cx: IRIS.x, cy: IRIS.y, r: 268, "stroke-dasharray": "120 60 10 60", pathLength: 1000 })),
    s("circle", { class: "fx-ping", cx: IRIS.x, cy: IRIS.y, r: 120 }),
    s("circle", { class: "fx-ping fx-ping2", cx: IRIS.x, cy: IRIS.y, r: 120 }));
  const tilt = h("div", { class: "fx-tilt" }, h("div", { class: "fx-orb", "aria-hidden": "true" }), eyeSvg, arcs);
  const zoomer = h("div", { class: "fx-zoomer" }, tilt);
  return { stage: h("div", { class: "fx-stage", role: "img", "aria-label": "MIRGAB" }, zoomer), zoomer, tilt, eyeSvg, pupil: eyeSvg.querySelector(".fx-pupil") };
}

export function landingPage(view, onEnter) {
  stopLanding();
  const canvas = h("canvas", { class: "ld-canvas", "aria-hidden": "true" });
  const zoom = h("div", { class: "fx-zoom", "aria-hidden": "true" });
  const enter = h("button", { class: "ld-enter", type: "button" },
    h("span", { class: "ld-enter-glow", "aria-hidden": "true" }),
    h("span", { lang: "en" }, "Enter MIRGAB"), h("i", { "aria-hidden": "true" }, "|"), h("span", { lang: "ar" }, "ادخل مرقاب"));
  const langBtn = langPicker(() => landingPage(view, onEnter), "ld-lang");
  const fx = falconStage();
  const root = h("section", { class: "ld", "aria-label": "MIRGAB" },
    canvas, fx.stage, zoom,
    h("div", { class: "ld-top" },
      h("div", { class: "ld-brand" },
        h("img", { src: "/assets/falcon-sm.png", alt: "", width: "56", height: "34", class: "brand-falcon on-dark" }),
        h("img", { src: "/assets/falcon-sm-ink.png", alt: "", width: "56", height: "34", class: "brand-falcon on-light" }),
        h("span", { class: "brand-text" }, h("span", { class: "brand-ar", lang: "ar", dir: "rtl" }, "مرقاب"), h("b", { lang: "en", dir: "ltr" }, "MIRGAB"))),
      h("div", { class: "ld-tools" }, themeBtn(), langBtn)),
    h("div", { class: "ld-copy" },
      h("h1", {}, t("ld.title")),
      h("p", {}, t("ld.sub")),
      h("div", { class: "ld-actions" }, enter)));
  view.replaceChildren(root);
  document.body.dataset.page = "landing";

  // ------------------------------------------------------------------ ambient particles (light, theme-aware)
  const ctx = canvas.getContext("2d");
  let W = 0, H = 0, DPR = 1, raf = 0, alive = true;
  const dots = Array.from({ length: 70 }, () => ({ x: Math.random(), y: Math.random(), z: 0.3 + Math.random() * 0.7, v: 0.00004 + Math.random() * 0.00012 }));
  const resize = () => {
    DPR = Math.min(2, window.devicePixelRatio || 1);
    W = root.clientWidth; H = root.clientHeight;
    canvas.width = W * DPR; canvas.height = H * DPR; canvas.style.width = `${W}px`; canvas.style.height = `${H}px`;
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
  };
  resize();

  // ------------------------------------------------------------------ pointer: 3D tilt + pupil tracking (smoothed)
  let tx = 0, ty = 0, cx = 0, cy = 0, entering = false, t0 = performance.now();
  const onMove = (e) => {
    const p = e.touches ? e.touches[0] : e;
    const r = fx.stage.getBoundingClientRect();
    tx = Math.max(-1, Math.min(1, (p.clientX - (r.left + r.width / 2)) / (window.innerWidth / 2)));
    ty = Math.max(-1, Math.min(1, (p.clientY - (r.top + r.height / 2)) / (window.innerHeight / 2)));
  };
  const frame = (now) => {
    if (!alive) return;
    const dark = document.documentElement.classList.contains("dark");
    ctx.clearRect(0, 0, W, H);
    for (const d of dots) {
      d.y -= d.v * 16; if (d.y < -0.02) { d.y = 1.02; d.x = Math.random(); }
      ctx.globalAlpha = (dark ? 0.55 : 0.35) * d.z;
      ctx.fillStyle = dark ? "#7dd3fc" : "#0e7490";
      ctx.beginPath(); ctx.arc(d.x * W + (cx * 14 * d.z), d.y * H + (cy * 10 * d.z), 1.1 * d.z + 0.3, 0, 6.283); ctx.fill();
    }
    ctx.globalAlpha = 1;
    if (!entering) {
      // idle "saccades" when the pointer is still, so the eye keeps scanning on phones too
      const idle = (now - t0) / 1000;
      const ix = tx || Math.sin(idle * 0.7) * 0.45, iy = ty || Math.sin(idle * 0.53 + 1) * 0.3;
      cx += (ix - cx) * 0.06; cy += (iy - cy) * 0.06;
      fx.tilt.style.transform = `rotateY(${cx * 14}deg) rotateX(${-cy * 10}deg)`;
      fx.pupil.setAttribute("transform", `translate(${cx * 16} ${cy * 9})`);
    }
    raf = requestAnimationFrame(frame);
  };
  window.addEventListener("pointermove", onMove, { passive: true });
  window.addEventListener("touchmove", onMove, { passive: true });
  const onResize = () => resize();
  window.addEventListener("resize", onResize);

  // ------------------------------------------------------------------ enter: fly into the pupil
  enter.addEventListener("click", () => {
    if (entering) return;
    entering = true;
    sessionStorage.setItem("mirqab.entered", "1");
    const go = () => { stopLanding(); onEnter(); };
    if (REDUCED) { root.classList.add("entering-soft"); setTimeout(go, 250); return; }
    // the pupil's on-screen position becomes the origin of the zoom
    const pr = fx.pupil.querySelector("circle:nth-of-type(2)").getBoundingClientRect();
    const sr = root.getBoundingClientRect();
    const px = pr.left + pr.width / 2 - sr.left, py = pr.top + pr.height / 2 - sr.top;
    const sc = (Math.hypot(Math.max(px, W - px), Math.max(py, H - py)) / (pr.width / 2)) * 1.15;
    const zr = fx.zoomer.getBoundingClientRect();
    fx.zoomer.style.transformOrigin = `${pr.left + pr.width / 2 - zr.left}px ${pr.top + pr.height / 2 - zr.top}px`;
    zoom.style.setProperty("--x", `${px}px`); zoom.style.setProperty("--y", `${py}px`); zoom.style.setProperty("--r0", `${pr.width / 2}px`);
    root.classList.add("entering");
    fx.zoomer.animate([{ transform: "scale(1)" }, { transform: `scale(${sc})` }], { duration: 1150, easing: "cubic-bezier(.7,0,.25,1)", fill: "forwards" });
    zoom.animate([{ opacity: 0, clipPath: `circle(${pr.width / 2}px at ${px}px ${py}px)` },
      { opacity: 1, offset: 0.55, clipPath: `circle(${pr.width}px at ${px}px ${py}px)` },
      { opacity: 1, clipPath: `circle(${Math.hypot(W, H)}px at ${px}px ${py}px)` }], { duration: 1150, easing: "cubic-bezier(.7,0,.25,1)", fill: "forwards" });
    setTimeout(() => {
      go();
      // the app fades in from the pupil's colour
      const veil = h("div", { class: "fx-veil", "aria-hidden": "true" });
      document.body.append(veil);
      veil.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 650, easing: "ease-out", fill: "forwards" }).onfinish = () => veil.remove();
    }, 1100);
  });

  if (REDUCED) { root.classList.add("reduced"); } else raf = requestAnimationFrame(frame);
  scene = {
    stop() {
      alive = false; cancelAnimationFrame(raf);
      window.removeEventListener("pointermove", onMove); window.removeEventListener("touchmove", onMove);
      window.removeEventListener("resize", onResize);
      if (document.body.dataset.page === "landing") delete document.body.dataset.page;
    },
  };
}
