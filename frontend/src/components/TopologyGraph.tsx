import { useEffect, useRef } from "react";

/**
 * A rotating 3-D view of the hosts and devices an engagement has touched.
 *
 * It is drawn on a plain 2-D canvas rather than pulled in through WebGL: the scene is
 * a few hundred points at most, the projection is a couple of rotations and a divide,
 * and staying on the 2-D context keeps it inside the window's strict CSP with no extra
 * dependency. Nodes cluster by zone, links are the connections we have observed, and
 * depth is carried by size and opacity so the shape reads even while it turns.
 *
 * It auto-rotates gently, and a drag orbits it. Honoured under prefers-reduced-motion.
 */

export type DeviceType =
  | "server"
  | "database"
  | "router"
  | "endpoint"
  | "cloud"
  | "firewall"
  | "unknown"
  // Application-graph node kinds (share the renderer with device kinds).
  | "page"
  | "api"
  | "asset"
  | "form"
  | "redirect";

export interface TopoNode {
  id: string;
  label: string;
  type: DeviceType;
  zone: string;
  /** 0..1 — how much this node stands out (traffic volume, findings). Scales its dot. */
  weight?: number;
}

export interface TopoLink {
  source: string;
  target: string;
}

interface Placed extends TopoNode {
  x: number;
  y: number;
  z: number;
}

const TYPE_FALLBACK: Record<DeviceType, string> = {
  server: "#5bb5aa",
  database: "#8098d9",
  router: "#d9b061",
  endpoint: "#7fa8c9",
  cloud: "#b48ad6",
  firewall: "#e0917a",
  unknown: "#8a93a3",
  // application-graph kinds
  page: "#5bb5aa",
  api: "#8098d9",
  asset: "#8a93a3",
  form: "#d9b061",
  redirect: "#7fa8c9",
};

/** Resolve a CSS custom property to a concrete colour, with a fallback. */
function cssVar(name: string, fallback: string): string {
  if (typeof window === "undefined") return fallback;
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

/** Deterministic pseudo-random in [0,1) from an integer seed — a stable layout per node. */
function rand(seed: number): number {
  const x = Math.sin(seed * 12.9898) * 43758.5453;
  return x - Math.floor(x);
}

/**
 * Lay the nodes out in 3-D: one cluster per zone spread around a ring, each node
 * placed on a small sphere about its zone's centre by a golden-angle spiral so the
 * members fan out evenly rather than piling up.
 */
function layout(nodes: TopoNode[]): Placed[] {
  const zones = Array.from(new Set(nodes.map((n) => n.zone)));
  const zoneCentre = new Map<string, [number, number, number]>();
  const ringR = zones.length > 1 ? 150 : 0;
  zones.forEach((z, i) => {
    const a = (i / Math.max(1, zones.length)) * Math.PI * 2;
    const y = zones.length > 1 ? (i % 2 === 0 ? -34 : 34) : 0;
    zoneCentre.set(z, [Math.cos(a) * ringR, y, Math.sin(a) * ringR]);
  });

  const byZone = new Map<string, TopoNode[]>();
  for (const n of nodes) {
    const arr = byZone.get(n.zone) ?? [];
    arr.push(n);
    byZone.set(n.zone, arr);
  }

  const placed: Placed[] = [];
  const golden = Math.PI * (3 - Math.sqrt(5));
  for (const [zone, members] of byZone) {
    const [cx, cy, cz] = zoneCentre.get(zone) ?? [0, 0, 0];
    const count = members.length;
    const spread = 30 + count * 7;
    members.forEach((n, i) => {
      if (count === 1) {
        placed.push({ ...n, x: cx, y: cy, z: cz });
        return;
      }
      const t = (i + 0.5) / count;
      const inclination = Math.acos(1 - 2 * t);
      const azimuth = golden * i;
      const r = spread * (0.55 + 0.45 * rand(i + zone.length));
      placed.push({
        ...n,
        x: cx + r * Math.sin(inclination) * Math.cos(azimuth),
        y: cy + r * Math.cos(inclination) * 0.7,
        z: cz + r * Math.sin(inclination) * Math.sin(azimuth),
      });
    });
  }
  return placed;
}

export function TopologyGraph({
  nodes,
  links,
  height = 420,
  onNodeClick,
}: {
  nodes: TopoNode[];
  links: TopoLink[];
  height?: number;
  /** A node was clicked (not dragged). Carries its id. */
  onNodeClick?: (id: string) => void;
}) {
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  // Kept in a ref so the click handler reads the latest callback without re-subscribing.
  const clickRef = useRef(onNodeClick);
  clickRef.current = onNodeClick;
  // Kept in refs so the animation loop reads live values without re-subscribing.
  const rot = useRef({ x: -0.35, y: 0.5 });
  const drag = useRef<{ on: boolean; px: number; py: number; moved: boolean }>({
    on: false,
    px: 0,
    py: 0,
    moved: false,
  });
  const autoRef = useRef(true);
  const dataRef = useRef<{ placed: Placed[]; links: TopoLink[] }>({ placed: [], links: [] });
  const hoverRef = useRef<string | null>(null);
  const zoomRef = useRef(1);
  const nudgeZoom = (factor: number) => {
    zoomRef.current = Math.max(0.4, Math.min(3, zoomRef.current * factor));
  };
  const resetView = () => {
    zoomRef.current = 1;
    rot.current = { x: -0.35, y: 0.5 };
  };

  useEffect(() => {
    dataRef.current = { placed: layout(nodes), links };
  }, [nodes, links]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const accent = cssVar("--accent", TYPE_FALLBACK.server);
    const accent2 = cssVar("--accent-2", TYPE_FALLBACK.database);
    const colors = {
      ...TYPE_FALLBACK,
      server: accent,
      database: accent2,
      page: accent,
      api: accent2,
    } as Record<DeviceType, string>;

    const reduced =
      typeof window !== "undefined" &&
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

    // The wrapper drives the size — never the canvas itself. The canvas is absolutely
    // positioned inside it, so its pixel dimensions can't feed back into the layout.
    const wrap = wrapRef.current ?? canvas.parentElement;
    let width = wrap?.clientWidth ?? 600;
    let dpr = Math.min(window.devicePixelRatio || 1, 2);
    const resize = () => {
      width = wrap?.clientWidth || 600;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    const ro = new ResizeObserver(resize);
    if (wrap) ro.observe(wrap);

    const project = (p: Placed) => {
      const { x: rx, y: ry } = rot.current;
      const cosY = Math.cos(ry);
      const sinY = Math.sin(ry);
      const cosX = Math.cos(rx);
      const sinX = Math.sin(rx);
      // rotate around Y, then X
      const x1 = p.x * cosY - p.z * sinY;
      const z1 = p.x * sinY + p.z * cosY;
      const y1 = p.y * cosX - z1 * sinX;
      const z2 = p.y * sinX + z1 * cosX;
      const fov = 620;
      const f = fov / (fov + z2 + 260);
      const z = zoomRef.current;
      return {
        sx: width / 2 + x1 * f * z,
        sy: height / 2 + y1 * f * z,
        depth: z2,
        f,
      };
    };

    let raf = 0;
    const frame = () => {
      const { placed, links: lk } = dataRef.current;
      if (autoRef.current && !drag.current.on && !reduced) {
        rot.current.y += 0.0025;
      }

      ctx.clearRect(0, 0, width, height);

      const pts = new Map<string, ReturnType<typeof project>>();
      for (const n of placed) pts.set(n.id, project(n));

      // Links first, dimmer with depth so the far side of the graph recedes.
      ctx.lineWidth = 1;
      for (const l of lk) {
        const a = pts.get(l.source);
        const b = pts.get(l.target);
        if (!a || !b) continue;
        const t = (a.f + b.f) / 2;
        ctx.strokeStyle = `rgba(140, 152, 170, ${0.05 + t * 0.16})`;
        ctx.beginPath();
        ctx.moveTo(a.sx, a.sy);
        ctx.lineTo(b.sx, b.sy);
        ctx.stroke();
      }

      // Nodes, painted far-to-near so nearer dots sit on top.
      const order = [...placed].sort(
        (m, n) => (pts.get(m.id)!.depth ?? 0) - (pts.get(n.id)!.depth ?? 0),
      );
      const zoom = zoomRef.current;
      for (const n of order) {
        const p = pts.get(n.id)!;
        const base = 3.2 + (n.weight ?? 0.3) * 6;
        const r = Math.max(1.6, base * p.f * Math.sqrt(zoom));
        const color = colors[n.type] ?? colors.unknown;
        const alpha = 0.45 + p.f * 0.55;
        const hovered = hoverRef.current === n.id;

        // soft halo
        ctx.beginPath();
        ctx.arc(p.sx, p.sy, r * (hovered ? 3.4 : 2.4), 0, Math.PI * 2);
        ctx.fillStyle = withAlpha(color, hovered ? 0.28 : 0.12 * p.f);
        ctx.fill();

        // core — a shape per device type, so the kind reads without the legend
        drawShape(ctx, n.type, p.sx, p.sy, r);
        ctx.fillStyle = withAlpha(color, alpha);
        ctx.fill();
        ctx.lineWidth = 1;
        ctx.strokeStyle = withAlpha("#0c0e12", 0.5);
        ctx.stroke();

        // label only for the near nodes or the hovered one, to keep it legible
        if (hovered || p.f > 0.92) {
          ctx.font = `${hovered ? 12 : 11}px system-ui, sans-serif`;
          ctx.fillStyle = `rgba(216, 220, 228, ${hovered ? 1 : 0.35 + p.f * 0.5})`;
          ctx.textBaseline = "middle";
          ctx.fillText(n.label, p.sx + r + 5, p.sy);
        }
      }

      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);

    // ---- interaction ----
    const onDown = (e: PointerEvent) => {
      drag.current = { on: true, px: e.clientX, py: e.clientY, moved: false };
      canvas.setPointerCapture(e.pointerId);
    };
    const onMove = (e: PointerEvent) => {
      const rect = canvas.getBoundingClientRect();
      if (drag.current.on) {
        const dx = e.clientX - drag.current.px;
        const dy = e.clientY - drag.current.py;
        drag.current.px = e.clientX;
        drag.current.py = e.clientY;
        if (Math.abs(dx) + Math.abs(dy) > 2) drag.current.moved = true;
        rot.current.y += dx * 0.006;
        rot.current.x = Math.max(-1.2, Math.min(1.2, rot.current.x + dy * 0.006));
        return;
      }
      // hover pick
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      let best: string | null = null;
      let bestD = 16 * 16;
      for (const n of dataRef.current.placed) {
        const p = project(n);
        const d = (p.sx - mx) ** 2 + (p.sy - my) ** 2;
        if (d < bestD) {
          bestD = d;
          best = n.id;
        }
      }
      if (best !== hoverRef.current) {
        hoverRef.current = best;
        canvas.style.cursor = best ? "pointer" : "grab";
      }
    };
    const onUp = (e: PointerEvent) => {
      const wasDrag = drag.current.moved;
      drag.current.on = false;
      canvas.style.cursor = "grab";
      try {
        canvas.releasePointerCapture(e.pointerId);
      } catch {
        /* pointer already released */
      }
      // A click, not an orbit: pick the node under the cursor and report it.
      if (!wasDrag && clickRef.current) {
        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        let best: string | null = null;
        let bestD = 18 * 18;
        for (const n of dataRef.current.placed) {
          const pt = project(n);
          const d = (pt.sx - mx) ** 2 + (pt.sy - my) ** 2;
          if (d < bestD) {
            bestD = d;
            best = n.id;
          }
        }
        if (best) clickRef.current(best);
      }
    };
    const onLeave = () => {
      hoverRef.current = null;
    };

    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      zoomRef.current = Math.max(0.4, Math.min(3, zoomRef.current * (e.deltaY < 0 ? 1.1 : 0.9)));
    };

    canvas.style.cursor = "grab";
    canvas.addEventListener("pointerdown", onDown);
    canvas.addEventListener("pointermove", onMove);
    canvas.addEventListener("pointerup", onUp);
    canvas.addEventListener("pointerleave", onLeave);
    canvas.addEventListener("wheel", onWheel, { passive: false });

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      canvas.removeEventListener("pointerdown", onDown);
      canvas.removeEventListener("pointermove", onMove);
      canvas.removeEventListener("pointerup", onUp);
      canvas.removeEventListener("pointerleave", onLeave);
      canvas.removeEventListener("wheel", onWheel);
    };
  }, [height]);

  return (
    <div ref={wrapRef} className="topo-canvas" style={{ height }}>
      <canvas ref={canvasRef} />
      <div className="topo-zoom">
        <button type="button" aria-label="Zoom in" onClick={() => nudgeZoom(1.2)}>
          +
        </button>
        <button type="button" aria-label="Zoom out" onClick={() => nudgeZoom(1 / 1.2)}>
          −
        </button>
        <button type="button" aria-label="Reset view" title="Reset view" onClick={resetView}>
          ⟳
        </button>
      </div>
    </div>
  );
}

/** Trace the outline of a device shape centred at (cx, cy). Caller fills and strokes. */
function drawShape(
  ctx: CanvasRenderingContext2D,
  type: DeviceType,
  cx: number,
  cy: number,
  r: number,
) {
  ctx.beginPath();
  switch (type) {
    case "endpoint":
    case "asset": {
      // rounded square
      const s = r * 1.7;
      const rad = Math.min(3, s * 0.25);
      roundRect(ctx, cx - s / 2, cy - s / 2, s, s, rad);
      break;
    }
    case "router":
    case "redirect": {
      // diamond
      const d = r * 1.4;
      ctx.moveTo(cx, cy - d);
      ctx.lineTo(cx + d, cy);
      ctx.lineTo(cx, cy + d);
      ctx.lineTo(cx - d, cy);
      ctx.closePath();
      break;
    }
    case "firewall":
    case "form": {
      // triangle (shield / input)
      const t = r * 1.5;
      ctx.moveTo(cx, cy - t);
      ctx.lineTo(cx + t * 0.9, cy + t * 0.7);
      ctx.lineTo(cx - t * 0.9, cy + t * 0.7);
      ctx.closePath();
      break;
    }
    case "database": {
      // cylinder: top ellipse, body, bottom curve
      const w = r * 1.3;
      const h = r * 1.6;
      const ey = h * 0.28;
      ctx.moveTo(cx - w, cy - h + ey);
      ctx.lineTo(cx - w, cy + h - ey);
      ctx.ellipse(cx, cy + h - ey, w, ey, 0, Math.PI, 0, true);
      ctx.lineTo(cx + w, cy - h + ey);
      ctx.ellipse(cx, cy - h + ey, w, ey, 0, 0, Math.PI * 2);
      break;
    }
    case "cloud":
    case "api": {
      // hexagon
      const hr = r * 1.5;
      for (let i = 0; i < 6; i++) {
        const a = (Math.PI / 3) * i - Math.PI / 6;
        const px = cx + hr * Math.cos(a);
        const py = cy + hr * Math.sin(a);
        if (i === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      }
      ctx.closePath();
      break;
    }
    default:
      // server / unknown: circle
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
  }
}

function roundRect(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  w: number,
  h: number,
  r: number,
) {
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

/** Blend a hex or already-rgba colour with an alpha, tolerant of `#rgb`/`#rrggbb`. */
function withAlpha(color: string, alpha: number): string {
  const a = Math.max(0, Math.min(1, alpha));
  if (color.startsWith("#")) {
    let hex = color.slice(1);
    if (hex.length === 3) hex = hex.split("").map((c) => c + c).join("");
    const n = parseInt(hex, 16);
    const r = (n >> 16) & 255;
    const g = (n >> 8) & 255;
    const b = n & 255;
    return `rgba(${r}, ${g}, ${b}, ${a})`;
  }
  return color;
}
