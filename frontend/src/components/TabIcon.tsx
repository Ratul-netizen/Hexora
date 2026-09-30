import type { ReactNode } from "react";

/**
 * The line icons that sit at the head of each sidebar item.
 *
 * Stroke-only, drawn in `currentColor`, so an icon takes the muted, hover or active
 * colour of the button around it without any per-state wiring. One weight, one grid
 * (24×24), so the strip reads as a set rather than a collection.
 */

const ICONS: Record<string, ReactNode> = {
  dashboard: (
    <>
      <rect x="3" y="3" width="7" height="9" rx="1" />
      <rect x="14" y="3" width="7" height="5" rx="1" />
      <rect x="14" y="12" width="7" height="9" rx="1" />
      <rect x="3" y="16" width="7" height="5" rx="1" />
    </>
  ),
  setup: (
    <>
      <line x1="4" y1="7" x2="20" y2="7" />
      <line x1="4" y1="12" x2="20" y2="12" />
      <line x1="4" y1="17" x2="20" y2="17" />
      <circle cx="9" cy="7" r="2.2" />
      <circle cx="15" cy="12" r="2.2" />
      <circle cx="8" cy="17" r="2.2" />
    </>
  ),
  history: (
    <>
      <path d="M3 12a9 9 0 1 0 2.6-6.4L3 8" />
      <path d="M3 3v5h5" />
      <path d="M12 8v4l3 2" />
    </>
  ),
  repeater: (
    <>
      <path d="M17 2l4 4-4 4" />
      <path d="M3 11V9a4 4 0 0 1 4-4h14" />
      <path d="M7 22l-4-4 4-4" />
      <path d="M21 13v2a4 4 0 0 1-4 4H3" />
    </>
  ),
  decoder: (
    <>
      <path d="M8 3H7a2 2 0 0 0-2 2v4a2 2 0 0 1-2 2 2 2 0 0 1 2 2v4a2 2 0 0 0 2 2h1" />
      <path d="M16 3h1a2 2 0 0 1 2 2v4a2 2 0 0 0 2 2 2 2 0 0 0-2 2v4a2 2 0 0 1-2 2h-1" />
    </>
  ),
  websockets: <path d="M22 12h-4l-3 8L9 4l-3 8H2" />,
  matchreplace: (
    <>
      <path d="M8 4L4 8l4 4" />
      <path d="M4 8h13a3 3 0 0 1 3 3v1" />
      <path d="M16 20l4-4-4-4" />
      <path d="M20 16H7a3 3 0 0 1-3-3v-1" />
    </>
  ),
  import: (
    <>
      <path d="M12 3v12" />
      <path d="M7 10l5 5 5-5" />
      <path d="M4 21h16" />
    </>
  ),
  identifiers: (
    <>
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <circle cx="8" cy="11" r="2" />
      <path d="M14 10h4" />
      <path d="M14 14h4" />
      <path d="M5 16.5c.4-1.6 1.6-2.5 3-2.5s2.6.9 3 2.5" />
    </>
  ),
  crawler: (
    <>
      <circle cx="6" cy="6" r="2" />
      <circle cx="18" cy="6" r="2" />
      <circle cx="12" cy="18" r="2" />
      <path d="M6 8v1a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V8" />
      <path d="M12 13v3" />
    </>
  ),
  sitemap: (
    <>
      <circle cx="6" cy="6" r="2" />
      <circle cx="6" cy="18" r="2" />
      <circle cx="18" cy="12" r="2" />
      <path d="M8 6h5a3 3 0 0 1 3 3v1" />
      <path d="M8 18h5a3 3 0 0 0 3-3v-1" />
    </>
  ),
  scan: (
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="M21 21l-4.3-4.3" />
    </>
  ),
  checks: (
    <>
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <path d="M8 12l3 3 5-6" />
    </>
  ),
  fuzzer: <path d="M13 2L4 14h6l-1 8 9-12h-6l1-8z" />,
  race: (
    <>
      <path d="M13 5l7 7-7 7" />
      <path d="M4 5l7 7-7 7" />
    </>
  ),
  sequencer: (
    <>
      <line x1="4" y1="9" x2="20" y2="9" />
      <line x1="4" y1="15" x2="20" y2="15" />
      <line x1="10" y1="3" x2="8" y2="21" />
      <line x1="16" y1="3" x2="14" y2="21" />
    </>
  ),
  domxss: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M3 9h18" />
      <circle cx="6" cy="6.5" r="0.6" />
      <circle cx="8.5" cy="6.5" r="0.6" />
    </>
  ),
  authz: (
    <>
      <path d="M12 3l8 3v5.5c0 4.3-3.4 7.6-8 8.5-4.6-.9-8-4.2-8-8.5V6z" />
      <path d="M9 12l2 2 4-4" />
    </>
  ),
  llm: (
    <>
      <path d="M12 3l1.7 4.3L18 9l-4.3 1.7L12 15l-1.7-4.3L6 9l4.3-1.7z" />
      <path d="M18 14l.8 2 2 .8-2 .8-.8 2-.8-2-2-.8 2-.8z" />
    </>
  ),
  oob: (
    <>
      <circle cx="12" cy="12" r="2" />
      <path d="M7.8 7.8a6 6 0 0 0 0 8.4" />
      <path d="M16.2 7.8a6 6 0 0 1 0 8.4" />
      <path d="M4.9 4.9a10 10 0 0 0 0 14.2" />
      <path d="M19.1 4.9a10 10 0 0 1 0 14.2" />
    </>
  ),
  findings: (
    <>
      <path d="M4 3v18" />
      <path d="M4 4h13l-2 4 2 4H4" />
    </>
  ),
  report: (
    <>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <path d="M14 2v6h6" />
      <path d="M8 13h8" />
      <path d="M8 17h6" />
    </>
  ),
  snapshots: (
    <>
      <path d="M12 3l9 5-9 5-9-5z" />
      <path d="M3 13l9 5 9-5" />
    </>
  ),
  programme: (
    <>
      <line x1="9" y1="6" x2="20" y2="6" />
      <line x1="9" y1="12" x2="20" y2="12" />
      <line x1="9" y1="18" x2="20" y2="18" />
      <circle cx="4.5" cy="6" r="1.1" />
      <circle cx="4.5" cy="12" r="1.1" />
      <circle cx="4.5" cy="18" r="1.1" />
    </>
  ),
  license: (
    <>
      <circle cx="8" cy="15" r="4" />
      <path d="M10.8 12.2L20 3" />
      <path d="M16 5l3 3" />
    </>
  ),
  toolkit: (
    <>
      <path d="M14.7 6.3a4 4 0 0 0-5.4 5.2L3 17.8 6.2 21l6.3-6.3a4 4 0 0 0 5.2-5.4l-2.6 2.6-2.2-2.2 2.6-2.6z" />
    </>
  ),
};

export function TabIcon({ id }: { id: string }) {
  const glyph = ICONS[id];
  if (!glyph) return null;
  return (
    <svg
      className="tab-icon"
      viewBox="0 0 24 24"
      width="16"
      height="16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {glyph}
    </svg>
  );
}
